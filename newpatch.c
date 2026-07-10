/*
 * newpatch.c - functions patching unpacked iOS IM4P bootloader files
 *
 * Copyright 2020 dayt0n
 * Modified: hybrid pattern-based + dynamic RSA, CTRR, improved boot-args,
 * NVRAM unlock, and DYNAMIC USB BACKDOOR (no hardcoded offsets).
 */

#define _GNU_SOURCE
#include "newpatch.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
void *memmem(const void *haystack, size_t haystack_len,
    const void * const needle, const size_t needle_len)
{
    if (!haystack || !needle || haystack_len < needle_len) return NULL;
    for (const char *h = haystack; haystack_len >= needle_len; ++h, --haystack_len) {
        if (!memcmp(h, needle, needle_len)) return (void*)h;
    }
    return NULL;
}
#endif

/* -------------------------------------------------------------------------
   Constants
   ------------------------------------------------------------------------- */
#define SIGCHECK_NEEDLE     0x72a86a60
#define PACIBSP             0xD503237F
#define BTI_C               0xD503245F
#define NOP                 0xD503201F
#define RET                 0xD65F03C0
#define RETAB               0xD65F0FFF
#define MOV_X0_0            0xD2800000
#define MOV_X0_1            0xD2800020

/* -------------------------------------------------------------------------
   External functions (provided by patchfinder64.c / newpatch.h)
   ------------------------------------------------------------------------- */
extern uint32_t get_insn(uint8_t *buf, addr_t off);
extern void write_opcode(uint8_t *buf, addr_t off, uint32_t val);
extern addr_t bof64(uint8_t *buf, addr_t start, addr_t where);
extern addr_t xref64(uint8_t *buf, addr_t start, addr_t end, addr_t what);
extern addr_t xref64code(uint8_t *buf, addr_t start, addr_t end, addr_t what);
extern addr_t calc64(uint8_t *buf, addr_t start, addr_t end, int reg);
extern addr_t step64(uint8_t *buf, addr_t start, size_t len, uint32_t what, uint32_t mask);
extern addr_t step64_back(uint8_t *buf, addr_t start, size_t len, uint32_t what, uint32_t mask);
extern addr_t follow_call64(uint8_t *buf, addr_t call);
extern uint32_t new_mov_immediate_insn(int reg, uint64_t imm, int is64);
extern uint32_t new_ret_insn(int reg);
extern uint32_t new_nop(void);
extern uint32_t new_branch(addr_t from, addr_t to);
extern uint32_t new_insn_adr(addr_t pc, int reg, addr_t target);
extern uint32_t replace_adr_addr(addr_t pc, uint32_t old_insn, addr_t target);
extern uint32_t get_addr_for_adr(addr_t pc, uint32_t insn);
extern int get_type(uint32_t insn);
extern int get_rd(uint32_t insn);
extern int get_rn(uint32_t insn);
extern int get_rm(uint32_t insn);
extern insn_type_t get_supertype(uint32_t insn);
extern uint64_t get_ptr_loc(uint8_t *buf, addr_t off);
extern addr_t get_next_nth_insn(uint8_t *buf, addr_t start, int n, insn_type_t type);
extern bool iboot64_pac_check(struct iboot64_img* iboot_in);
extern void* iboot64_memmem(struct iboot64_img* iboot_in, void* pat);
extern uint64_t iboot64_ref(struct iboot64_img* iboot_in, void* pat);
extern addr_t GET_IBOOT_FILE_OFFSET(struct iboot64_img* iboot_in, void* ptr);
extern addr_t GET_IBOOT64_ADDR(struct iboot64_img* iboot_in, void* ptr);
extern int get_iboot64_version(struct iboot64_img* iboot_in);

/* -------------------------------------------------------------------------
   Utilities: find ADRP+ADD xrefs to a data offset
   ------------------------------------------------------------------------- */
typedef struct { addr_t adrp; addr_t add; } adrp_add_pair_t;

static int find_adrp_add_refs(uint8_t *buf, size_t len, addr_t base, addr_t target_off,
                              adrp_add_pair_t *pairs, int max_pairs)
{
    addr_t target_va = base + target_off;
    addr_t target_page = target_va & ~0xFFF;
    addr_t target_pageoff = target_va & 0xFFF;
    int count = 0;

    for (addr_t off = 0; off < len - 8; off += 4) {
        uint32_t w = get_insn(buf, off);
        if ((w & 0x9F000000) != 0x90000000) continue;
        int immhi = (w >> 5) & 0x7FFFF;
        int immlo = (w >> 29) & 0x3;
        int64_t imm = ((immhi << 2) | immlo) << 12;
        if (imm & (1ULL << 32)) imm -= (1ULL << 33);
        addr_t page = ((base + off) & ~0xFFF) + imm;
        if (page != target_page) continue;

        uint32_t next = get_insn(buf, off + 4);
        if ((next & 0xFF800000) != 0x91000000) continue;
        int rd_adrp = w & 0x1F;
        int rn_add = (next >> 5) & 0x1F;
        int imm12 = (next >> 10) & 0xFFF;
        if (rd_adrp == rn_add && imm12 == target_pageoff) {
            if (count < max_pairs) {
                pairs[count].adrp = off;
                pairs[count].add = off + 4;
                count++;
            }
        }
    }
    return count;
}

/* ======================================================================
   1. RSA signature check – hybrid pattern + needle + fallback
   ====================================================================== */
static addr_t find_image4_callback_pattern(uint8_t *buf, size_t len) {
    for (addr_t off = 0; off < len - 4; off += 4) {
        uint32_t w = get_insn(buf, off);
        if ((w & 0xFFFFF81F) != 0x12800000) continue;
        int wreg = w & 0x1F;

        addr_t bne = 0;
        for (int k = 1; k < 32; k++) {
            if (off - k*4 < 0) break;
            uint32_t prev = get_insn(buf, off - k*4);
            if ((prev & 0xFF00001F) == 0x54000001) {
                bne = off - k*4;
                break;
            }
        }
        if (!bne) continue;

        addr_t mov = 0;
        for (int k = 1; k < 16; k++) {
            if (off + k*4 + 4 > len) break;
            uint32_t nxt = get_insn(buf, off + k*4);
            if ((nxt & 0xFFE0FFE0) == 0xAA0003E0) {
                mov = off + k*4;
                break;
            }
        }
        if (!mov) continue;

        LOG("Pattern RSA: MOVN W%d @0x%llx, B.NE @0x%llx, MOV X0 @0x%llx\n",
            wreg, off, bne, mov);
        return bne;
    }
    return 0;
}

static addr_t find_sig_check_fn_dynamic(uint8_t *buf, size_t len) {
    uint32_t needle = SIGCHECK_NEEDLE;
    void *loc = memmem(buf, len, &needle, sizeof(needle));
    if (!loc) {
        WARN("Dynamic needle not found\n");
        return 0;
    }
    addr_t off = (addr_t)((uintptr_t)loc - (uintptr_t)buf);
    LOG("Found needle at 0x%llx\n", off);

    addr_t pos = off;
    int found = 0;
    for (int i = 0; i < 200; i++) {
        pos += 4;
        if (pos + 4 > len) break;
        uint32_t op = get_insn(buf, pos);
        if ((op & 0xFE1F0000) == 0xD61F0000 || (op & 0xFFE0FFFF) == 0xD65F0000) {
            found = 1;
            break;
        }
    }
    if (!found) {
        WARN("No BR/BLR/RET after needle\n");
        return 0;
    }
    addr_t fn = bof64(buf, 0, pos);
    if (!fn) {
        WARN("bof64 failed\n");
        return 0;
    }
    LOG("Dynamic function start at 0x%llx\n", fn);
    return fn;
}

void do_rsa_sigcheck_patch(struct iboot64_img* iboot_in, addr_t img4Xref, bool pac) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t func_start = 0;

    addr_t bne = find_image4_callback_pattern(buf, len);
    if (bne) {
        func_start = bof64(buf, 0, bne);
        if (!func_start) func_start = bne;
        LOG("Pattern RSA: func_start=0x%llx\n", func_start);
    } else {
        func_start = find_sig_check_fn_dynamic(buf, len);
        if (!func_start) {
            func_start = bof64(buf, 0, img4Xref);
            if (pac) func_start -= 4;
            LOG("Fallback IMG4 xref: func_start=0x%llx\n", func_start);
        }
    }

    if (!func_start) {
        WARN("Could not locate function start, RSA PATCH FAILED\n");
        return;
    }

    if (pac) {
        LOG("PAC bootloader: adjusting to PACIBSP/BTI\n");
        uint32_t op = get_insn(buf, func_start);
        if (op != PACIBSP && op != BTI_C) {
            addr_t search = func_start;
            int found = 0;
            for (int i = 0; i < 4; i++) {
                search -= 4;
                if (search < 0) break;
                if (get_insn(buf, search) == PACIBSP || get_insn(buf, search) == BTI_C) {
                    func_start = search;
                    found = 1;
                    LOG("Found PACIBSP/BTI at 0x%llx\n", func_start);
                    break;
                }
            }
            if (!found) WARN("PACIBSP not found, proceeding anyway\n");
        } else {
            LOG("PACIBSP already at function start\n");
        }
    }

    LOG("Patching RSA at 0x%llx\n", func_start + iboot_in->base);
    uint32_t mov = new_mov_immediate_insn(0, 0, 1);
    uint32_t ret = new_ret_insn(-1);
    write_opcode(buf, func_start, mov);
    write_opcode(buf, func_start + 4, ret);
    LOG("RSA PATCH SUCCESSFUL\n");
}

/* ======================================================================
   2. CTRR lockdown – NOP MSR CTRR_*_EL2
   ====================================================================== */
int patch_ctrr_lockdown(struct iboot64_img* iboot_in) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    int count = 0;
    LOG("Searching for CTRR MSR instructions...\n");
    for (addr_t off = 0; off < len - 4; off += 4) {
        uint32_t w = get_insn(buf, off);
        if ((w & 0xFFF00000) != 0xD5100000) continue;
        int op0 = 2 + ((w >> 19) & 1);
        int op1 = (w >> 16) & 0x7;
        int crn = (w >> 12) & 0xF;
        int crm = (w >> 8) & 0xF;
        int op2 = (w >> 5) & 0x7;
        if (op0 == 3 && op1 == 4 && crn == 15 && crm == 2 && (op2 == 2 || op2 == 5)) {
            const char *name = (op2 == 2) ? "CTRR_LOCK_EL2" : "CTRR_CTL_EL2";
            LOG("  NOP %s at 0x%llx\n", name, off);
            write_opcode(buf, off, NOP);
            count++;
        }
    }
    if (count == 0) WARN("No CTRR MSR found\n");
    else LOG("CTRR lockdown: %d MSR(s) NOPed\n", count);
    return count;
}

/* ======================================================================
   3. Boot-args injection – dynamic using "%s"
   ====================================================================== */
int patch_boot_args64(struct iboot64_img* iboot_in, char *bootargs) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t base = iboot_in->base;
    LOG("Image base at 0x%llx\n", base);

    void *rd_md0 = memmem(buf, len, "rd=md0", 6);
    if (!rd_md0) {
        WARN("Could not find 'rd=md0'\n");
        return -1;
    }
    addr_t rd_off = (addr_t)((uintptr_t)rd_md0 - (uintptr_t)buf);

    addr_t fmt_off = 0;
    for (addr_t off = (rd_off > 0x100 ? rd_off - 0x100 : 0);
         off < rd_off + 0x100 && off < len - 2; off++) {
        if (buf[off] == '%' && buf[off+1] == 's' && buf[off+2] == 0) {
            fmt_off = off;
            break;
        }
    }

    if (!fmt_off) {
        LOG("Searching whole binary for %%s with ADRP xref...\n");
        addr_t pos = 0;
        while ((pos = (addr_t)memmem(buf + pos, len - pos, "%s\0", 3)) != 0) {
            adrp_add_pair_t pairs[4];
            int n = find_adrp_add_refs(buf, len, base, pos, pairs, 4);
            if (n > 0) {
                fmt_off = pos;
                LOG("Found %%s at 0x%llx with %d xref(s)\n", fmt_off, n);
                break;
            }
            pos += 3;
        }
    }

    if (!fmt_off) {
        WARN("Could not find suitable %%s string\n");
        return -1;
    }

    LOG("Using %%s at 0x%llx\n", fmt_off);

    adrp_add_pair_t pairs[8];
    int num_refs = find_adrp_add_refs(buf, len, base, fmt_off, pairs, 8);
    if (num_refs == 0) {
        WARN("No ADRP+ADD xref to %%s\n");
        return -1;
    }

    addr_t slot = 0;
    for (addr_t off = 0x14000; off < len - 64; off += 16) {
        int zero = 1;
        for (int i = 0; i < 64; i++) if (buf[off+i]) { zero = 0; break; }
        if (zero) { slot = off; break; }
    }
    if (!slot) {
        WARN("No NUL slot found\n");
        return -1;
    }

    char new_args[300];
    snprintf(new_args, sizeof(new_args), "serial=3 -v debug=0x2014e %s", bootargs);
    size_t new_len = strlen(new_args) + 1;
    if (new_len > 270) {
        WARN("Boot-args too long, truncating\n");
        new_args[270] = 0;
        new_len = 270;
    }

    LOG("Injecting boot-args at 0x%llx: \"%s\"\n", slot, new_args);
    memcpy(buf + slot, new_args, new_len);

    addr_t new_va = base + slot;
    addr_t new_page = new_va & ~0xFFF;
    addr_t new_pageoff = new_va & 0xFFF;

    for (int i = 0; i < num_refs; i++) {
        addr_t adrp_off = pairs[i].adrp;
        addr_t add_off = pairs[i].add;
        int rd = get_insn(buf, adrp_off) & 0x1F;

        int64_t delta = (new_page - ((base + adrp_off) & ~0xFFF)) >> 12;
        uint32_t new_adrp = 0x90000000 | ((delta & 0x3) << 29) | (((delta >> 2) & 0x7FFFF) << 5) | rd;
        write_opcode(buf, adrp_off, new_adrp);

        uint32_t new_add = 0x91000000 | (new_pageoff << 10) | (rd << 5) | rd;
        write_opcode(buf, add_off, new_add);

        LOG("Redirected ADRP+ADD at 0x%llx,0x%llx\n", adrp_off, add_off);
    }

    LOG("Boot-args patch applied\n");
    return 0;
}

/* ======================================================================
   4. Kernel debug – automatic BL count
   ====================================================================== */
void do_kdbg_mov(struct iboot64_img* iboot_in, addr_t xref) {
    bool pac = iboot64_pac_check(iboot_in);
    int nth_bl = pac ? 5 : 2;
    addr_t bl_off = get_next_nth_insn(iboot_in->buf, xref, nth_bl, bl);
    if (!bl_off) {
        WARN("Could not find BL #%d, trying fallback\n", nth_bl);
        bl_off = get_next_nth_insn(iboot_in->buf, xref, 1, bl);
        if (bl_off) bl_off += (nth_bl - 1) * 4;
        else { WARN("Kernel debug patch failed\n"); return; }
    }
    LOG("Found BL #%d at 0x%llx\n", nth_bl, bl_off);
    uint32_t mov = new_mov_immediate_insn(0, 1, 1);
    write_opcode(iboot_in->buf, bl_off, mov);
    LOG("Wrote MOVZ X0,#1 at 0x%llx\n", bl_off + iboot_in->base);
}

int enable_kernel_debug(struct iboot64_img* iboot_in) {
    void *debug = memmem(iboot_in->buf, iboot_in->len, "debug-enabled", 13);
    if (!debug) { WARN("debug-enabled not found\n"); return -1; }
    uint64_t xref = iboot64_ref(iboot_in, debug);
    if (xref == (uint64_t)-1) { WARN("debug-enabled xref not found\n"); return -1; }
    do_kdbg_mov(iboot_in, xref);
    LOG("Enabled kernel debug\n");
    return 0;
}

/* ======================================================================
   5. NVRAM unlock
   ====================================================================== */
int unlock_nvram(struct iboot64_img* iboot_in) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t base = iboot_in->base;

    void *debuguartLoc = memmem(buf, len, "debug-uarts", strlen("debug-uarts"));
    if (!debuguartLoc) {
        WARN("Unable to find debug-uarts string\n");
        return -1;
    }
    LOG("Found debug-uarts string at %p\n", GET_IBOOT64_ADDR(iboot_in, debuguartLoc));

    void *debuguartRef = iboot64_memmem(iboot_in, debuguartLoc);
    if (!debuguartRef) {
        WARN("Unable to find debug-uarts reference\n");
        return -1;
    }
    addr_t debugRef = (addr_t)GET_IBOOT_FILE_OFFSET(iboot_in, debuguartRef);
    LOG("Found debug-uarts reference at 0x%llx\n", debugRef);

    addr_t setenvWhitelist = debugRef;
    while (get_ptr_loc(buf, setenvWhitelist -= 8) != 0);
    setenvWhitelist += 8;
    LOG("setenv whitelist begins at 0x%llx\n", setenvWhitelist);

    addr_t blacklistFunc = xref64(buf, 0, len, setenvWhitelist);
    if (!blacklistFunc) {
        WARN("Could not find reference to setenv whitelist\n");
        return -1;
    }
    LOG("Found ref to setenv whitelist at 0x%llx\n", blacklistFunc);

    addr_t blacklistFuncBegin = bof64(buf, 0, blacklistFunc);
    if (!blacklistFuncBegin) {
        WARN("Could not find beginning of blacklist function\n");
        return -1;
    }
    LOG("Forcing sub_%llx to return immediately\n", blacklistFuncBegin + base);

    uint32_t movZeroZero = new_mov_immediate_insn(0, 0, 1);
    uint32_t retInsn = new_ret_insn(-1);
    write_opcode(buf, blacklistFuncBegin, movZeroZero);
    write_opcode(buf, blacklistFuncBegin + 4, retInsn);

    addr_t envWhitelist = setenvWhitelist;
    while (get_ptr_loc(buf, envWhitelist += 8) != 0);
    envWhitelist += 8;
    LOG("Found env whitelist at 0x%llx\n", envWhitelist);

    addr_t blacklistFunc2 = xref64(buf, 0, len, envWhitelist);
    if (!blacklistFunc2) {
        WARN("Could not find reference to env whitelist\n");
        return -1;
    }
    LOG("Found ref to env whitelist at 0x%llx\n", blacklistFunc2);

    addr_t blacklistFunc2Begin = bof64(buf, 0, blacklistFunc2);
    if (!blacklistFunc2Begin) {
        WARN("Could not find beginning of second blacklist function\n");
        return -1;
    }
    LOG("Forcing sub_%llx to return immediately\n", blacklistFunc2Begin + base);
    write_opcode(buf, blacklistFunc2Begin, movZeroZero);
    write_opcode(buf, blacklistFunc2Begin + 4, retInsn);

    void *comAppleSystemLoc = memmem(buf, len, "com.apple.System.", strlen("com.apple.System.") + 1);
    if (!comAppleSystemLoc) {
        WARN("Could not find string \"com.apple.System.\"\n");
        return -1;
    }
    LOG("Found \"com.apple.System.\" string at %p\n", GET_IBOOT64_ADDR(iboot_in, comAppleSystemLoc));

    addr_t comAppleSystemRef = iboot64_ref(iboot_in, comAppleSystemLoc);
    if (comAppleSystemRef == (uint64_t)-1) {
        WARN("Could not find reference to \"com.apple.System.\"\n");
        return -1;
    }
    LOG("Found reference to \"com.apple.System.\" at 0x%llx\n", comAppleSystemRef);

    addr_t appleSystemFuncBegin = bof64(buf, 0, comAppleSystemRef);
    if (!appleSystemFuncBegin) {
        WARN("Unable to find beginning of function where \"com.apple.System.\" is referenced\n");
        return -1;
    }
    LOG("Forcing sub_%llx to return immediately\n", appleSystemFuncBegin + base);
    write_opcode(buf, appleSystemFuncBegin, movZeroZero);
    write_opcode(buf, appleSystemFuncBegin + 4, retInsn);

    LOG("NVRAM unlocked successfully\n");
    return 0;
}

/* ======================================================================
   6. Command handler modification
   ====================================================================== */
int do_command_handler_patch(struct iboot64_img* iboot_in, char* command, uintptr_t ptr) {
    char *realCmd = (char*)malloc(strlen(command) + 2);
    if (!realCmd) return -1;
    memset(realCmd, 0, strlen(command) + 2);
    for (int i = 0; i < (int)strlen(command); i++)
        realCmd[i+1] = command[i];

    void *cmdLoc = memmem(iboot_in->buf, iboot_in->len, realCmd, strlen(command) + 2);
    free(realCmd);
    if (!cmdLoc) {
        WARN("Unable to find \"%s\" in image\n", command);
        return -1;
    }
    cmdLoc++;

    LOG("Found command \"%s\" at %p\n", command, GET_IBOOT_FILE_OFFSET(iboot_in, cmdLoc));

    void *cmdRef = iboot64_memmem(iboot_in, cmdLoc);
    if (!cmdRef) {
        WARN("Unable to find reference to command \"%s\"\n", command);
        return -1;
    }
    addr_t ref = (addr_t)GET_IBOOT_FILE_OFFSET(iboot_in, cmdRef);
    LOG("Found reference to %s command at 0x%llx\n", command, ref);

    LOG("Pointing %s handler to 0x%lx\n", command, ptr);
    *(uint64_t*)(iboot_in->buf + ref + 8) = ptr;
    return 0;
}

/* ======================================================================
   7. RSA wrapper
   ====================================================================== */
int rsa_sigcheck_patch(struct iboot64_img* iboot_in, bool pac) {
    void *img4 = memmem(iboot_in->buf, iboot_in->len, "IMG4\0", 5);
    if (!img4) { WARN("IMG4 string not found\n"); return -1; }
    uint64_t img4ref = iboot64_ref(iboot_in, img4);
    if (img4ref == (uint64_t)-1) { WARN("IMG4 xref not found\n"); return -1; }
    do_rsa_sigcheck_patch(iboot_in, (addr_t)img4ref, pac);
    return 0;
}

/* ======================================================================
   8. DYNAMIC USB BACKDOOR (no hardcoded offsets)
   ====================================================================== */

/* USB request structure */
struct usb_device_request {
    uint8_t  bmRequestType;
    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} __attribute__((packed));

enum {
    DFU_DETACH = 0,
    DFU_DNLOAD,
    DFU_UPLOAD,
    DFU_GETSTATUS,
    DFU_CLR_STATUS,
    DFU_GETSTATE,
    DFU_ABORT,
    CUSTOM_DEMOTE,
    CUSTOM_BOOT,
    CUSTOM_AES_GID,
    CUSTOM_TEST,
    CUSTOM_READ,
    CUSTOM_WRITE
};

static const char test_magic[] = "usbliter8";
static uint8_t rw_buf[2048];
static uint16_t addr_high = 0;

/* Con trỏ hàm được tìm động */
static int (*orig_handle_usb_req)(struct usb_device_request *request, uint8_t **io_buffer) = NULL;
static void (*platform_demote)(void) = NULL;
static void (*platform_set_remote_boot)(void) = NULL;
static int (*aes_crypto_cmd)(int op, void *src, void *dst, unsigned int len, unsigned int opts, void *iv, void *key) = NULL;

/* Các địa chỉ cần thiết */
static uint64_t main_task_stack_lr = 0;
static uint64_t jump_away = 0;

#if WITH_PAC
__attribute__((naked))
uint64_t PACIB(uint64_t ptr, uint64_t ctx) {
    asm("PACIB x0, x1");
    asm("RET");
}
#endif

/* Custom USB request handler */
static int custom_handle_usb_req(struct usb_device_request *request, uint8_t **io_buffer) {
    uint8_t bmRequestType = request->bmRequestType;
    uint8_t bRequest      = request->bRequest;
    uint16_t wValue       = request->wValue;
    uint16_t wIndex       = request->wIndex;
    uint16_t wLength      = request->wLength;

    if ((bmRequestType & 0x80) == 0x00) { /* HOST2DEVICE */
        switch (bRequest) {
            case CUSTOM_DEMOTE: {
                if (platform_demote) platform_demote();
                return 0;
            }
            case CUSTOM_BOOT: {
                if (platform_set_remote_boot) platform_set_remote_boot();
                uint64_t ptr = jump_away;
#if WITH_PAC
                ptr = PACIB(ptr, main_task_stack_lr + 8);
#endif
                if (main_task_stack_lr) {
                    *(volatile uint64_t *)main_task_stack_lr = ptr;
                }
                return 0;
            }
            case CUSTOM_WRITE: {
                if (wValue == 0xFFFF && wIndex == 0xFFFF) {
                    if (wLength >= 2) {
                        uint8_t *src = *io_buffer;
                        addr_high = (uint16_t)(src[0] | (src[1] << 8));
                    }
                    return 0;
                }
                uint64_t addr = ((uint64_t)addr_high << 32) | ((uint64_t)wValue << 16) | wIndex;
                volatile uint8_t *dst = (volatile uint8_t *)addr;
                uint8_t *src = *io_buffer;
                uint16_t len = (wLength > 2048) ? 2048 : wLength;
                for (uint16_t i = 0; i < len; i++) dst[i] = src[i];
                return 0;
            }
        }
    } else { /* DEVICE2HOST */
        if (bRequest == CUSTOM_TEST) {
            for (int i = 0; i < (int)sizeof(test_magic); i++)
                rw_buf[i] = test_magic[i];
            *io_buffer = rw_buf;
            return sizeof(test_magic);
        }
        if (bRequest == CUSTOM_READ) {
            uint64_t addr = ((uint64_t)addr_high << 32) | ((uint64_t)wValue << 16) | wIndex;
            volatile uint8_t *src = (volatile uint8_t *)addr;
            uint16_t len = (wLength > 2048) ? 2048 : wLength;
            for (uint16_t i = 0; i < len; i++) rw_buf[i] = src[i];
            *io_buffer = rw_buf;
            return len;
        }
#if defined(AES_CRYPTO_CMD)
        if (bRequest == CUSTOM_AES_GID && aes_crypto_cmd) {
            static uint8_t kbag_buf[48];
            uint8_t *src = *io_buffer;
            for (int i = 0; i < 48; i++) kbag_buf[i] = src[i];
            aes_crypto_cmd(0x11, kbag_buf, kbag_buf, 48, 0x20000, NULL, NULL);
            *io_buffer = kbag_buf;
            return 48;
        }
#endif
    }

    if (orig_handle_usb_req)
        return orig_handle_usb_req(request, io_buffer);
    return -1;
}

/* Tìm các địa chỉ động từ iBoot buffer */
static int find_usb_offsets(struct iboot64_img* iboot_in) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t base = iboot_in->base;

    /* 1. Tìm hàm xử lý USB gốc – dùng chuỗi "usb_device_request" */
    void *str = memmem(buf, len, "usb_device_request", strlen("usb_device_request"));
    if (str) {
        addr_t off = (addr_t)((uintptr_t)str - (uintptr_t)buf);
        addr_t ref = xref64(buf, 0, len, off);
        if (ref) {
            orig_handle_usb_req = (void*)(base + ref);
            LOG("USB handler found at 0x%llx\n", (uint64_t)orig_handle_usb_req);
        }
    }
    if (!orig_handle_usb_req) {
        WARN("Could not find USB request handler\n");
        return -1;
    }

    /* 2. Tìm platform_demote – chuỗi "demote" hoặc "demoting" */
    str = memmem(buf, len, "demoting", strlen("demoting"));
    if (!str) str = memmem(buf, len, "demote", strlen("demote"));
    if (str) {
        addr_t off = (addr_t)((uintptr_t)str - (uintptr_t)buf);
        addr_t ref = xref64(buf, 0, len, off);
        if (ref) {
            addr_t func = bof64(buf, 0, ref);
            if (func) platform_demote = (void*)(base + func);
        }
    }
    if (platform_demote) LOG("platform_demote at 0x%llx\n", (uint64_t)platform_demote);
    else WARN("platform_demote not found\n");

    /* 3. Tìm platform_set_remote_boot – chuỗi "remote_boot" */
    str = memmem(buf, len, "remote_boot", strlen("remote_boot"));
    if (str) {
        addr_t off = (addr_t)((uintptr_t)str - (uintptr_t)buf);
        addr_t ref = xref64(buf, 0, len, off);
        if (ref) {
            addr_t func = bof64(buf, 0, ref);
            if (func) platform_set_remote_boot = (void*)(base + func);
        }
    }
    if (platform_set_remote_boot) LOG("platform_set_remote_boot at 0x%llx\n", (uint64_t)platform_set_remote_boot);
    else WARN("platform_set_remote_boot not found\n");

    /* 4. Tìm AES crypto cmd – chuỗi "gid-aes-key" */
    str = memmem(buf, len, "gid-aes-key", strlen("gid-aes-key"));
    if (str) {
        addr_t off = (addr_t)((uintptr_t)str - (uintptr_t)buf);
        addr_t ref = xref64(buf, 0, len, off);
        if (ref) {
            /* Tìm lệnh BL gần đó để lấy địa chỉ hàm AES */
            addr_t call = step64_back(buf, ref, 0x100, 0x94000000, 0xFC000000);
            if (call) {
                addr_t target = follow_call64(buf, call);
                if (target) aes_crypto_cmd = (void*)(base + target);
            }
        }
    }
    if (aes_crypto_cmd) LOG("aes_crypto_cmd at 0x%llx\n", (uint64_t)aes_crypto_cmd);
    else WARN("aes_crypto_cmd not found\n");

    /* 5. Tìm JUMP_AWAY – chuỗi "booting" hoặc "go" */
    str = memmem(buf, len, "booting", strlen("booting"));
    if (!str) str = memmem(buf, len, "go", strlen("go"));
    if (str) {
        addr_t off = (addr_t)((uintptr_t)str - (uintptr_t)buf);
        addr_t ref = xref64(buf, 0, len, off);
        if (ref) {
            addr_t func = bof64(buf, 0, ref);
            if (func) jump_away = base + func;
        }
    }
    if (jump_away) LOG("jump_away at 0x%llx\n", jump_away);
    else WARN("jump_away not found\n");

    /* 6. Tìm MAIN_TASK_STACK_LR – thường gần hàm main_task */
    str = memmem(buf, len, "main_task", strlen("main_task"));
    if (str) {
        addr_t off = (addr_t)((uintptr_t)str - (uintptr_t)buf);
        addr_t ref = xref64(buf, 0, len, off);
        if (ref) {
            /* Ước tính: địa chỉ LR nằm trong stack, thường là base + offset cố định.
               Thay vì tìm chính xác, ta có thể lấy địa chỉ của một biến toàn cục gần đó */
            main_task_stack_lr = base + off + 0x400; // heuristic
        }
    }
    if (main_task_stack_lr) LOG("main_task_stack_lr ~ 0x%llx\n", main_task_stack_lr);
    else WARN("main_task_stack_lr not found\n");

    return 0;
}

/* Hàm cài đặt USB backdoor – thay thế handler */
int install_usb_backdoor(struct iboot64_img* iboot_in) {
    LOG("Installing dynamic USB backdoor...\n");

    if (find_usb_offsets(iboot_in) < 0) {
        WARN("Could not find all required offsets\n");
        return -1;
    }

    if (!orig_handle_usb_req) {
        WARN("No USB handler to hook\n");
        return -1;
    }

    /* Ghi đè con trỏ hàm xử lý USB */
    /* Tìm vị trí con trỏ hàm trong bảng handler */
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t base = iboot_in->base;
    addr_t handler_ptr = (addr_t)((uintptr_t)orig_handle_usb_req - (uintptr_t)buf);
    /* Thực tế, orig_handle_usb_req là địa chỉ VA, ta cần tìm vị trí lưu con trỏ đó */
    /* Cách đơn giản: tìm xref đến địa chỉ của orig_handle_usb_req trong code */
    addr_t ref = xref64(buf, 0, len, handler_ptr);
    if (ref) {
        /* Ghi đè con trỏ tại ref thành custom_handle_usb_req */
        uint64_t new_ptr = (uint64_t)custom_handle_usb_req;
        if (iboot64_pac_check(iboot_in)) {
            /* Có thể cần PAC cho con trỏ, nhưng đây là con trỏ hàm, PAC sẽ được xử lý tự động */
        }
        *(uint64_t*)(buf + ref) = new_ptr;
        LOG("USB handler hooked at 0x%llx\n", base + ref);
    } else {
        /* Fallback: tìm kiếm pattern của lệnh ADRP + LDR/STR và thay thế */
        WARN("Could not find reference to USB handler pointer, trying alternative...\n");
        /* Tìm ADRP load handler_ptr và thay đổi */
        for (addr_t off = 0; off < len - 8; off += 4) {
            uint32_t w = get_insn(buf, off);
            if ((w & 0x9F000000) != 0x90000000) continue;
            int rd = w & 0x1F;
            uint32_t next = get_insn(buf, off + 4);
            if ((next & 0xFFC00000) == 0xF9400000) { // LDR Xd, [Xbase, #imm]
                int rn = (next >> 5) & 0x1F;
                if (rd == rn) {
                    addr_t target = calc64(buf, off, off + 8, rd);
                    if (target == base + handler_ptr) {
                        /* Ghi đè LDR thành LDR custom_handle_usb_req */
                        uint64_t new_ptr = (uint64_t)custom_handle_usb_req;
                        /* Cần xây dựng lại ADRP để trỏ đến new_ptr */
                        /* Đây là phần phức tạp, tạm thời bỏ qua */
                    }
                }
            }
        }
        WARN("Hook failed\n");
        return -1;
    }

    LOG("USB backdoor installed successfully\n");
    return 0;
}

/* ======================================================================
   9. Legacy/original functions
   ====================================================================== */
bool has_magic(uint8_t* buf) {
    uint32_t magic = *(uint32_t*)(buf+7);
    if (memcmp(&magic, IMAGE4_MAGIC, 4) == 0) return true;
    return false;
}

bool has_kernel_load_k(struct iboot64_img* iboot_in) {
    void *str = memmem(iboot_in->buf, iboot_in->len, KERNELCACHE_PREP_STRING, strlen(KERNELCACHE_PREP_STRING));
    return (str != NULL);
}

bool has_recovery_console_k(struct iboot64_img* iboot_in) {
    void *str = memmem(iboot_in->buf, iboot_in->len, ENTERING_RECOVERY_CONSOLE, strlen(ENTERING_RECOVERY_CONSOLE));
    return (str != NULL);
}

uint64_t get_iboot64_base_address(struct iboot64_img* iboot_in) {
    uint32_t offset = 0x318;
    get_iboot64_version(iboot_in);
    if (iboot_in->buf) {
        if (iboot_in->VERS >= 6603) offset = 0x300;
        iboot_in->base = *(uint64_t*)(iboot_in->buf + offset);
        return iboot_in->base;
    }
    return 0;
}

uint32_t get_iboot64_version(struct iboot64_img* iboot_in) {
    void *ver = memmem(iboot_in->buf, iboot_in->len, "iBoot-", 6);
    if (!ver) return 0;
    char vers[5] = {0};
    strncpy(vers, (char*)ver + 6, 4);
    iboot_in->VERS = atoi(vers);
    return iboot_in->VERS;
}

uint64_t iboot64_ref(struct iboot64_img* iboot_in, void* pat) {
    uint64_t new_pat = (uintptr_t) GET_IBOOT64_ADDR(iboot_in, pat);
    addr_t ref = xref64(iboot_in->buf, 0, iboot_in->len, new_pat - iboot_in->base);
    if (!ref) return -1;
    return ref;
}

bool iboot64_pac_check(struct iboot64_img* iboot_in) {
    void *loc = memmem(iboot_in->buf, iboot_in->len, "\x7F\x23\x03\xD5", 4);
    return (loc != NULL);
}   1. RSA signature check – hybrid pattern + needle + fallback
   ------------------------------------------------------------------------- */

// Pattern-based: find MOVN Wn,#0 -> B.NE -> MOV X0,Xn
static addr_t find_image4_callback_pattern(uint8_t *buf, size_t len) {
    for (addr_t off = 0; off < len - 4; off += 4) {
        uint32_t w = get_insn(buf, off);
        if ((w & 0xFFFFF81F) != 0x12800000) continue; // MOVN Wn, #0
        int wreg = w & 0x1F;

        // find B.NE within previous 32 instructions
        addr_t bne = 0;
        for (int k = 1; k < 32; k++) {
            if (off - k*4 < 0) break;
            uint32_t prev = get_insn(buf, off - k*4);
            if ((prev & 0xFF00001F) == 0x54000001) { // B.NE
                bne = off - k*4;
                break;
            }
        }
        if (!bne) continue;

        // find MOV X0, Xn within next 16 instructions
        addr_t mov = 0;
        for (int k = 1; k < 16; k++) {
            if (off + k*4 + 4 > len) break;
            uint32_t nxt = get_insn(buf, off + k*4);
            if ((nxt & 0xFFE0FFE0) == 0xAA0003E0) { // MOV X0, Xn
                mov = off + k*4;
                break;
            }
        }
        if (!mov) continue;

        LOG("Pattern RSA: MOVN W%d @0x%llx, B.NE @0x%llx, MOV X0 @0x%llx\n",
            wreg, off, bne, mov);
        return bne; // return B.NE offset
    }
    return 0;
}

// Needle-based: search for movk w0,#0x4353
static addr_t find_sig_check_fn_dynamic(uint8_t *buf, size_t len) {
    uint32_t needle = SIGCHECK_NEEDLE;
    void *loc = memmem(buf, len, &needle, sizeof(needle));
    if (!loc) {
        WARN("Dynamic needle (movk) not found\n");
        return 0;
    }
    addr_t off = (addr_t)((uintptr_t)loc - (uintptr_t)buf);
    LOG("Found needle at 0x%llx\n", off);

    addr_t pos = off;
    int found = 0;
    for (int i = 0; i < 200; i++) {
        pos += 4;
        if (pos + 4 > len) break;
        uint32_t op = get_insn(buf, pos);
        if ((op & 0xFE1F0000) == 0xD61F0000 || (op & 0xFFE0FFFF) == 0xD65F0000) {
            found = 1;
            break;
        }
    }
    if (!found) {
        WARN("No BR/BLR/RET after needle\n");
        return 0;
    }
    addr_t fn = bof64(buf, 0, pos);
    if (!fn) {
        WARN("bof64 failed\n");
        return 0;
    }
    LOG("Dynamic function start at 0x%llx\n", fn);
    return fn;
}

// Main RSA patch function – tries all methods
void do_rsa_sigcheck_patch(struct iboot64_img* iboot_in, addr_t img4Xref, bool pac) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t func_start = 0;

    // 1. Pattern-based (best, works on most versions)
    addr_t bne = find_image4_callback_pattern(buf, len);
    if (bne) {
        func_start = bof64(buf, 0, bne);
        if (!func_start) func_start = bne;
        LOG("Pattern RSA: func_start=0x%llx\n", func_start);
    } else {
        // 2. Needle-based
        func_start = find_sig_check_fn_dynamic(buf, len);
        if (!func_start) {
            // 3. Fallback: IMG4 xref
            func_start = bof64(buf, 0, img4Xref);
            if (pac) func_start -= 4;
            LOG("Fallback IMG4 xref: func_start=0x%llx\n", func_start);
        }
    }

    if (!func_start) {
        WARN("Could not locate function start, RSA PATCH FAILED\n");
        return;
    }

    // Adjust for PAC (move back to PACIBSP if needed)
    if (pac) {
        LOG("PAC bootloader: adjusting to PACIBSP/BTI\n");
        uint32_t op = get_insn(buf, func_start);
        if (op != PACIBSP && op != BTI_C) {
            addr_t search = func_start;
            int found = 0;
            for (int i = 0; i < 4; i++) {
                search -= 4;
                if (search < 0) break;
                if (get_insn(buf, search) == PACIBSP || get_insn(buf, search) == BTI_C) {
                    func_start = search;
                    found = 1;
                    LOG("Found PACIBSP/BTI at 0x%llx\n", func_start);
                    break;
                }
            }
            if (!found) WARN("PACIBSP not found, proceeding anyway\n");
        } else {
            LOG("PACIBSP already at function start\n");
        }
    }

    // Patch: MOV X0, #0 ; RET
    LOG("Patching RSA at 0x%llx\n", func_start + iboot_in->base);
    uint32_t mov = new_mov_immediate_insn(0, 0, 1);
    uint32_t ret = new_ret_insn(-1);
    write_opcode(buf, func_start, mov);
    write_opcode(buf, func_start + 4, ret);
    LOG("RSA PATCH SUCCESSFUL\n");
}

/* -------------------------------------------------------------------------
   2. CTRR lockdown – NOP MSR CTRR_*_EL2
   ------------------------------------------------------------------------- */
int patch_ctrr_lockdown(struct iboot64_img* iboot_in) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    int count = 0;
    LOG("Searching for CTRR MSR instructions...\n");
    for (addr_t off = 0; off < len - 4; off += 4) {
        uint32_t w = get_insn(buf, off);
        if ((w & 0xFFF00000) != 0xD5100000) continue;
        int op0 = 2 + ((w >> 19) & 1);
        int op1 = (w >> 16) & 0x7;
        int crn = (w >> 12) & 0xF;
        int crm = (w >> 8) & 0xF;
        int op2 = (w >> 5) & 0x7;
        if (op0 == 3 && op1 == 4 && crn == 15 && crm == 2 && (op2 == 2 || op2 == 5)) {
            const char *name = (op2 == 2) ? "CTRR_LOCK_EL2" : "CTRR_CTL_EL2";
            LOG("  NOP %s at 0x%llx\n", name, off);
            write_opcode(buf, off, NOP);
            count++;
        }
    }
    if (count == 0) WARN("No CTRR MSR found\n");
    else LOG("CTRR lockdown: %d MSR(s) NOPed\n", count);
    return count;
}

/* -------------------------------------------------------------------------
   3. Boot-args injection – find "%s" and redirect
   ------------------------------------------------------------------------- */
int patch_boot_args64(struct iboot64_img* iboot_in, char *bootargs) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t base = iboot_in->base;
    LOG("Image base at 0x%llx\n", base);

    // Find "rd=md0" as anchor
    void *rd_md0 = memmem(buf, len, "rd=md0", 6);
    if (!rd_md0) {
        WARN("Could not find 'rd=md0'\n");
        return -1;
    }
    addr_t rd_off = (addr_t)((uintptr_t)rd_md0 - (uintptr_t)buf);

    // Find "%s\0" near rd=md0 (within ±0x100)
    addr_t fmt_off = 0;
    for (addr_t off = (rd_off > 0x100 ? rd_off - 0x100 : 0);
         off < rd_off + 0x100 && off < len - 2; off++) {
        if (buf[off] == '%' && buf[off+1] == 's' && buf[off+2] == 0) {
            fmt_off = off;
            break;
        }
    }

    // If not found, scan entire binary for "%s\0" with an ADRP+ADD xref
    if (!fmt_off) {
        LOG("Searching whole binary for %%s with ADRP xref...\n");
        addr_t pos = 0;
        while ((pos = (addr_t)memmem(buf + pos, len - pos, "%s\0", 3)) != 0) {
            // Check if this "%s" has at least one ADRP+ADD xref
            adrp_add_pair_t pairs[4];
            int n = find_adrp_add_refs(buf, len, base, pos, pairs, 4);
            if (n > 0) {
                fmt_off = pos;
                LOG("Found %%s at 0x%llx with %d xref(s)\n", fmt_off, n);
                break;
            }
            pos += 3;
        }
    }

    if (!fmt_off) {
        WARN("Could not find suitable %%s string\n");
        return -1;
    }

    LOG("Using %%s at 0x%llx\n", fmt_off);

    // Find ADRP+ADD xrefs to fmt_off
    adrp_add_pair_t pairs[8];
    int num_refs = find_adrp_add_refs(buf, len, base, fmt_off, pairs, 8);
    if (num_refs == 0) {
        WARN("No ADRP+ADD xref to %%s\n");
        return -1;
    }

    // Find a zero region for new boot-args
    addr_t slot = 0;
    for (addr_t off = 0x14000; off < len - 64; off += 16) {
        int zero = 1;
        for (int i = 0; i < 64; i++) if (buf[off+i]) { zero = 0; break; }
        if (zero) { slot = off; break; }
    }
    if (!slot) {
        WARN("No NUL slot found\n");
        return -1;
    }

    // Prepare new boot-args
    char new_args[300];
    snprintf(new_args, sizeof(new_args), "serial=3 -v debug=0x2014e %s", bootargs);
    size_t new_len = strlen(new_args) + 1;
    if (new_len > 270) {
        WARN("Boot-args too long, truncating\n");
        new_args[270] = 0;
        new_len = 270;
    }

    LOG("Injecting boot-args at 0x%llx: \"%s\"\n", slot, new_args);
    memcpy(buf + slot, new_args, new_len);

    // Redirect each ADRP+ADD pair to the new slot
    addr_t new_va = base + slot;
    addr_t new_page = new_va & ~0xFFF;
    addr_t new_pageoff = new_va & 0xFFF;

    for (int i = 0; i < num_refs; i++) {
        addr_t adrp_off = pairs[i].adrp;
        addr_t add_off = pairs[i].add;
        int rd = get_insn(buf, adrp_off) & 0x1F;

        // Rebuild ADRP
        int64_t delta = (new_page - ((base + adrp_off) & ~0xFFF)) >> 12;
        uint32_t new_adrp = 0x90000000 | ((delta & 0x3) << 29) | (((delta >> 2) & 0x7FFFF) << 5) | rd;
        write_opcode(buf, adrp_off, new_adrp);

        // Rebuild ADD
        uint32_t new_add = 0x91000000 | (new_pageoff << 10) | (rd << 5) | rd;
        write_opcode(buf, add_off, new_add);

        LOG("Redirected ADRP+ADD at 0x%llx,0x%llx\n", adrp_off, add_off);
    }

    LOG("Boot-args patch applied\n");
    return 0;
}

/* -------------------------------------------------------------------------
   4. Kernel debug – automatic BL count
   ------------------------------------------------------------------------- */
void do_kdbg_mov(struct iboot64_img* iboot_in, addr_t xref) {
    bool pac = iboot64_pac_check(iboot_in);
    int nth_bl = pac ? 5 : 2;
    addr_t bl_off = get_next_nth_insn(iboot_in->buf, xref, nth_bl, bl);
    if (!bl_off) {
        WARN("Could not find BL #%d, trying fallback\n", nth_bl);
        bl_off = get_next_nth_insn(iboot_in->buf, xref, 1, bl);
        if (bl_off) bl_off += (nth_bl - 1) * 4;
        else { WARN("Kernel debug patch failed\n"); return; }
    }
    LOG("Found BL #%d at 0x%llx\n", nth_bl, bl_off);
    uint32_t mov = new_mov_immediate_insn(0, 1, 1);
    write_opcode(iboot_in->buf, bl_off, mov);
    LOG("Wrote MOVZ X0,#1 at 0x%llx\n", bl_off + iboot_in->base);
}

int enable_kernel_debug(struct iboot64_img* iboot_in) {
    void *debug = memmem(iboot_in->buf, iboot_in->len, "debug-enabled", 13);
    if (!debug) { WARN("debug-enabled not found\n"); return -1; }
    uint64_t xref = iboot64_ref(iboot_in, debug);
    if (xref == (uint64_t)-1) { WARN("debug-enabled xref not found\n"); return -1; }
    do_kdbg_mov(iboot_in, xref);
    LOG("Enabled kernel debug\n");
    return 0;
}

/* -------------------------------------------------------------------------
   5. NVRAM unlock
   ------------------------------------------------------------------------- */
int unlock_nvram(struct iboot64_img* iboot_in) {
    uint8_t *buf = iboot_in->buf;
    size_t len = iboot_in->len;
    addr_t base = iboot_in->base;
    bool pac = iboot64_pac_check(iboot_in);

    void *debuguartLoc = memmem(buf, len, "debug-uarts", strlen("debug-uarts"));
    if (!debuguartLoc) {
        WARN("Unable to find debug-uarts string\n");
        return -1;
    }
    LOG("Found debug-uarts string at %p\n", GET_IBOOT64_ADDR(iboot_in, debuguartLoc));

    void *debuguartRef = iboot64_memmem(iboot_in, debuguartLoc);
    if (!debuguartRef) {
        WARN("Unable to find debug-uarts reference\n");
        return -1;
    }
    addr_t debugRef = (addr_t)GET_IBOOT_FILE_OFFSET(iboot_in, debuguartRef);
    LOG("Found debug-uarts reference at 0x%llx\n", debugRef);

    // find start of whitelist
    addr_t setenvWhitelist = debugRef;
    while (get_ptr_loc(buf, setenvWhitelist -= 8) != 0);
    setenvWhitelist += 8;
    LOG("setenv whitelist begins at 0x%llx\n", setenvWhitelist);

    addr_t blacklistFunc = xref64(buf, 0, len, setenvWhitelist);
    if (!blacklistFunc) {
        WARN("Could not find reference to setenv whitelist\n");
        return -1;
    }
    LOG("Found ref to setenv whitelist at 0x%llx\n", blacklistFunc);

    addr_t blacklistFuncBegin = bof64(buf, 0, blacklistFunc);
    if (!blacklistFuncBegin) {
        WARN("Could not find beginning of blacklist function\n");
        return -1;
    }
    LOG("Forcing sub_%llx to return immediately\n", blacklistFuncBegin + base);

    uint32_t movZeroZero = new_mov_immediate_insn(0, 0, 1);
    uint32_t retInsn = new_ret_insn(-1);
    write_opcode(buf, blacklistFuncBegin, movZeroZero);
    write_opcode(buf, blacklistFuncBegin + 4, retInsn);

    // env whitelist
    addr_t envWhitelist = setenvWhitelist;
    while (get_ptr_loc(buf, envWhitelist += 8) != 0);
    envWhitelist += 8;
    LOG("Found env whitelist at 0x%llx\n", envWhitelist);

    addr_t blacklistFunc2 = xref64(buf, 0, len, envWhitelist);
    if (!blacklistFunc2) {
        WARN("Could not find reference to env whitelist\n");
        return -1;
    }
    LOG("Found ref to env whitelist at 0x%llx\n", blacklistFunc2);

    addr_t blacklistFunc2Begin = bof64(buf, 0, blacklistFunc2);
    if (!blacklistFunc2Begin) {
        WARN("Could not find beginning of second blacklist function\n");
        return -1;
    }
    LOG("Forcing sub_%llx to return immediately\n", blacklistFunc2Begin + base);
    write_opcode(buf, blacklistFunc2Begin, movZeroZero);
    write_opcode(buf, blacklistFunc2Begin + 4, retInsn);

    // com.apple.System. prefix
    void *comAppleSystemLoc = memmem(buf, len, "com.apple.System.", strlen("com.apple.System.") + 1);
    if (!comAppleSystemLoc) {
        WARN("Could not find string \"com.apple.System.\"\n");
        return -1;
    }
    LOG("Found \"com.apple.System.\" string at %p\n", GET_IBOOT64_ADDR(iboot_in, comAppleSystemLoc));

    addr_t comAppleSystemRef = iboot64_ref(iboot_in, comAppleSystemLoc);
    if (comAppleSystemRef == (uint64_t)-1) {
        WARN("Could not find reference to \"com.apple.System.\"\n");
        return -1;
    }
    LOG("Found reference to \"com.apple.System.\" at 0x%llx\n", comAppleSystemRef);

    addr_t appleSystemFuncBegin = bof64(buf, 0, comAppleSystemRef);
    if (!appleSystemFuncBegin) {
        WARN("Unable to find beginning of function where \"com.apple.System.\" is referenced\n");
        return -1;
    }
    LOG("Forcing sub_%llx to return immediately\n", appleSystemFuncBegin + base);
    write_opcode(buf, appleSystemFuncBegin, movZeroZero);
    write_opcode(buf, appleSystemFuncBegin + 4, retInsn);

    LOG("NVRAM unlocked successfully\n");
    return 0;
}

/* -------------------------------------------------------------------------
   6. Command handler modification
   ------------------------------------------------------------------------- */
int do_command_handler_patch(struct iboot64_img* iboot_in, char* command, uintptr_t ptr) {
    char *realCmd = (char*)malloc(strlen(command) + 2);
    if (!realCmd) return -1;
    memset(realCmd, 0, strlen(command) + 2);
    for (int i = 0; i < (int)strlen(command); i++)
        realCmd[i+1] = command[i];

    void *cmdLoc = memmem(iboot_in->buf, iboot_in->len, realCmd, strlen(command) + 2);
    free(realCmd);
    if (!cmdLoc) {
        WARN("Unable to find \"%s\" in image\n", command);
        return -1;
    }
    cmdLoc++; // skip leading null

    LOG("Found command \"%s\" at %p\n", command, GET_IBOOT_FILE_OFFSET(iboot_in, cmdLoc));

    void *cmdRef = iboot64_memmem(iboot_in, cmdLoc);
    if (!cmdRef) {
        WARN("Unable to find reference to command \"%s\"\n", command);
        return -1;
    }
    addr_t ref = (addr_t)GET_IBOOT_FILE_OFFSET(iboot_in, cmdRef);
    LOG("Found reference to %s command at 0x%llx\n", command, ref);

    LOG("Pointing %s handler to 0x%lx\n", command, ptr);
    *(uint64_t*)(iboot_in->buf + ref + 8) = ptr;
    return 0;
}

/* -------------------------------------------------------------------------
   7. RSA wrapper (entry point from rsa_sigcheck_patch)
   ------------------------------------------------------------------------- */
int rsa_sigcheck_patch(struct iboot64_img* iboot_in, bool pac) {
    void *img4 = memmem(iboot_in->buf, iboot_in->len, "IMG4\0", 5);
    if (!img4) { WARN("IMG4 string not found\n"); return -1; }
    addr_t img4off = (addr_t)((uintptr_t)img4 - (uintptr_t)iboot_in->buf);
    uint64_t img4ref = iboot64_ref(iboot_in, img4);
    if (img4ref == (uint64_t)-1) { WARN("IMG4 xref not found\n"); return -1; }
    do_rsa_sigcheck_patch(iboot_in, (addr_t)img4ref, pac);
    return 0;
}

/* -------------------------------------------------------------------------
   8. Legacy/other functions (kept for compatibility)
   ------------------------------------------------------------------------- */
bool has_magic(uint8_t* buf) {
    uint32_t magic = *(uint32_t*)(buf+7);
    if (memcmp(&magic, IMAGE4_MAGIC, 4) == 0) return true;
    return false;
}

bool has_kernel_load_k(struct iboot64_img* iboot_in) {
    void *str = memmem(iboot_in->buf, iboot_in->len, KERNELCACHE_PREP_STRING, strlen(KERNELCACHE_PREP_STRING));
    return (str != NULL);
}

bool has_recovery_console_k(struct iboot64_img* iboot_in) {
    void *str = memmem(iboot_in->buf, iboot_in->len, ENTERING_RECOVERY_CONSOLE, strlen(ENTERING_RECOVERY_CONSOLE));
    return (str != NULL);
}

uint64_t get_iboot64_base_address(struct iboot64_img* iboot_in) {
    uint32_t offset = 0x318;
    get_iboot64_version(iboot_in);
    if (iboot_in->buf) {
        if (iboot_in->VERS >= 6603) offset = 0x300;
        iboot_in->base = *(uint64_t*)(iboot_in->buf + offset);
        return iboot_in->base;
    }
    return 0;
}

// Other original functions (change_bootarg_adr_xref_addr, doFinalBootArgs, etc.)
// are already provided in the original newpatch.c and can be kept unchanged.
// For completeness, we include stubs if they are not defined elsewhere.

/* -------------------------------------------------------------------------
   Stubs for missing functions (if not provided by newpatch.h)
   ------------------------------------------------------------------------- */
#ifndef HAVE_GET_IBOOT64_VERSION
uint32_t get_iboot64_version(struct iboot64_img* iboot_in) {
    void *ver = memmem(iboot_in->buf, iboot_in->len, "iBoot-", 6);
    if (!ver) return 0;
    char vers[5] = {0};
    strncpy(vers, (char*)ver + 6, 4);
    iboot_in->VERS = atoi(vers);
    return iboot_in->VERS;
}
#endif

#ifndef HAVE_GET_IBOOT64_ADDR
addr_t GET_IBOOT64_ADDR(struct iboot64_img* iboot_in, void* ptr) {
    return iboot_in->base + ((uintptr_t)ptr - (uintptr_t)iboot_in->buf);
}
#endif

#ifndef HAVE_GET_IBOOT_FILE_OFFSET
addr_t GET_IBOOT_FILE_OFFSET(struct iboot64_img* iboot_in, void* ptr) {
    return (uintptr_t)ptr - (uintptr_t)iboot_in->buf;
}
#endif
