/*
 * newpatch.h - function declarations and defines for newpatch.c
 *
 * Copyright 2020 dayt0n
 * Modified: fixed LOG/WARN macros.
 */

#pragma once
#include "patchfinder64.h"
#include "instructions.h"

#define ENTERING_RECOVERY_CONSOLE "Entering recovery mode, starting command prompt"
#define KERNELCACHE_PREP_STRING "__PAGEZERO"
#define IMAGE4_MAGIC "IM4P"
#define KERNEL_LOAD_STRING "__PAGEZERO"
#define DEFAULT_BOOTARGS_STRING "rd=md0 nand-enable-reformat=1 -progress"
#define OTHER_DEFAULT_BOOTARGS_STRING "rd=md0 -progress -restore"
#define CERT_STRING "Reliance on this"
#define PACIBSP_STR "\x7F\x23\x03\xD5"

struct iboot64_img {
    void* buf;
    size_t len;
    uint32_t VERS;
    uint32_t minor_vers;
    uint64_t base;
} __attribute__((packed));

// Sửa macro để tránh lỗi if-else
#define LOG(fmt, ...) do { printf("[+] " fmt, ##__VA_ARGS__); } while (0)
#define WARN(fmt, ...) do { printf("[!] " fmt, ##__VA_ARGS__); } while (0)

#define GET_IBOOT64_ADDR(iboot_in, x) (x - (uintptr_t) iboot_in->buf) + iboot_in->base
#define GET_IBOOT_FILE_OFFSET(iboot_in, x) (x - (uintptr_t) iboot_in->buf)

/* Original patch functions */
bool has_magic(uint8_t* buf);
int patch_boot_args64(struct iboot64_img* iboot_in, char* bootargs);
uint64_t get_iboot64_base_address(struct iboot64_img* iboot_in);
uint32_t get_iboot64_version(struct iboot64_img* iboot_in);
uint64_t iboot64_ref(struct iboot64_img* iboot_in, void* pat);
int enable_kernel_debug(struct iboot64_img* iboot_in);
int rsa_sigcheck_patch(struct iboot64_img* iboot_in, bool pac);
bool has_kernel_load_k(struct iboot64_img* iboot_in);
bool has_recovery_console_k(struct iboot64_img* iboot_in);
int do_command_handler_patch(struct iboot64_img* iboot_in, char* command, uintptr_t ptr);
int unlock_nvram(struct iboot64_img* iboot_in);
bool iboot64_pac_check(struct iboot64_img* iboot_in);
void *iboot64_memmem(struct iboot64_img* iboot_in, void* pat);

/* New additions */
int patch_ctrr_lockdown(struct iboot64_img* iboot_in);
int install_usb_backdoor(struct iboot64_img* iboot_in);
int patch_image_type(struct iboot64_img* iboot_in);
int patch_rootfs_bypass(struct iboot64_img* iboot_in);
int patch_panic_bypass(struct iboot64_img* iboot_in);
int patch_bootx_precondition(struct iboot64_img* iboot_in);
int patch_serial_labels(struct iboot64_img* iboot_in);

int patch_bootx_precondition(struct iboot64_img* iboot_in);
int patch_serial_labels(struct iboot64_img* iboot_in);
