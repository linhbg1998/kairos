/*
 * main.c - main file for using kairos, used to patch unpacked IM4P iOS bootloader images
 *
 * Copyright 2020 dayt0n
 * Modified: added CTRR, USB backdoor, image type bypass options.
 */

#include "newpatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Incorrect usage\nusage: %s [deciBoot] [patchediBoot] [OPTIONS]\n", argv[0]);
        printf("Options:\n");
        printf("\t-b [args]\t\tset boot-args\n");
        printf("\t-c [cmd] [location]\trelocate command handler\n");
        printf("\t-n\t\t\tunlock nvram\n");
        printf("\t-ctrr\t\t\tNOP CTRR lockdown MSRs\n");
        printf("\t-usb\t\t\tinstall USB backdoor (custom commands)\n");
        printf("\t-imgtype\t\tbypass image type checks\n");
        printf("\nExample usage:\n");
        printf("  %s iBEC.dec iBEC.patched -n -b \"-v debug=0x09\" -c \"go\" 0x830000300\n", argv[0]);
        printf("  %s iBEC.dec iBEC.patched -ctrr -usb -imgtype\n", argv[0]);
        return -1;
    }

    char* inFile = argv[1];
    char* outFile = argv[2];
    char* bootArgs = NULL;
    char* command_str = NULL;
    uint64_t command_ptr = 0;
    struct iboot64_img iboot_in;
    int ret = 0;
    memset(&iboot_in, 0, sizeof(iboot_in));
    bool doNvramUnlock = false;
    bool doCtrrLockdown = false;
    bool doUsbBackdoor = false;
    bool doImageType = false;

    // Parse options
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bootArgs = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 2 < argc) {
            command_str = argv[++i];
            sscanf(argv[++i], "0x%016llX", &command_ptr);
        } else if (strcmp(argv[i], "-n") == 0) {
            doNvramUnlock = true;
        } else if (strcmp(argv[i], "-ctrr") == 0) {
            doCtrrLockdown = true;
        } else if (strcmp(argv[i], "-usb") == 0) {
            doUsbBackdoor = true;
        } else if (strcmp(argv[i], "-imgtype") == 0) {
            doImageType = true;
        } else {
            WARN("Unknown option: %s\n", argv[i]);
        }
    }

    // Read input image
    FILE* fp = fopen(inFile, "rb");
    if (!fp) {
        printf("Error opening %s for reading\n", inFile);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    iboot_in.len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    iboot_in.buf = (uint8_t*)malloc(iboot_in.len);
    if (!iboot_in.buf) {
        printf("Error allocating 0x%lx bytes\n", iboot_in.len);
        return -1;
    }
    fread(iboot_in.buf, 1, iboot_in.len, fp);
    fflush(fp);
    fclose(fp);

    // Start patching
    LOG("Patching %s\n", inFile);
    if (has_magic(iboot_in.buf)) {
        WARN("%s does not appear to be stripped\n", inFile);
        return -1;
    }
    LOG("Base address: 0x%llx\n", get_iboot64_base_address(&iboot_in));
    bool pac = iboot64_pac_check(&iboot_in);

    // 1. Patches that require kernel load (boot-args, kernel debug)
    if (has_kernel_load_k(&iboot_in)) {
        LOG("Does have kernel load\n");
        if (bootArgs) {
            LOG("Patching boot-args...\n");
            ret = patch_boot_args64(&iboot_in, bootArgs);
            if (ret < 0)
                WARN("Failed to patch boot-args\n");
        }
        LOG("Enabling kernel debug...\n");
        ret = enable_kernel_debug(&iboot_in);
        if (ret < 0)
            WARN("Could not enable kernel debug\n");
    }

    // 2. Patches that require recovery console (command handler, NVRAM unlock)
    if (has_recovery_console_k(&iboot_in)) {
        if (command_str && (command_ptr != 0)) {
            LOG("Changing command handler %s to 0x%llx...\n", command_str, command_ptr);
            ret = do_command_handler_patch(&iboot_in, command_str, command_ptr);
            if (ret < 0)
                WARN("Failed to patch command handler for %s\n", command_str);
        }
        if (doNvramUnlock) {
            LOG("Unlocking nvram...\n");
            ret = unlock_nvram(&iboot_in);
            if (ret < 0)
                WARN("Failed to unlock nvram\n");
        }
    }

    // 3. CTRR lockdown (always available)
    if (doCtrrLockdown) {
        LOG("Applying CTRR lockdown...\n");
        ret = patch_ctrr_lockdown(&iboot_in);
        if (ret < 0)
            WARN("CTRR lockdown failed\n");
    }

    // 4. Image type bypass
    if (doImageType) {
        LOG("Patching image type checks...\n");
        ret = patch_image_type(&iboot_in);
        if (ret < 0)
            WARN("Image type patch failed\n");
    }

    // 5. RSA signature check patch (always)
    LOG("Patching out RSA signature check...\n");
    ret = rsa_sigcheck_patch(&iboot_in, pac);
    if (ret < 0)
        WARN("Error patching out RSA signature check\n");

    // 6. USB backdoor (install after all other patches)
    if (doUsbBackdoor) {
        LOG("Installing USB backdoor...\n");
        ret = install_usb_backdoor(&iboot_in);
        if (ret < 0)
            WARN("USB backdoor installation failed\n");
    }

    // Write output
    fp = fopen(outFile, "wb+");
    if (!fp) {
        printf("Error opening %s for writing\n", outFile);
        free(iboot_in.buf);
        return -1;
    }
    fwrite(iboot_in.buf, 1, iboot_in.len, fp);
    fflush(fp);
    fclose(fp);
    free(iboot_in.buf);
    LOG("Wrote patched image to %s\n", outFile);
    return 0;
}        }
    }

    // 3. CTRR lockdown (always available, no dependency)
    if (doCtrrLockdown) {
        LOG("Applying CTRR lockdown...\n");
        ret = patch_ctrr_lockdown(&iboot_in);
        if (ret < 0)
            WARN("CTRR lockdown failed\n");
    }

    // 4. RSA signature check patch (always)
    LOG("Patching out RSA signature check...\n");
    ret = rsa_sigcheck_patch(&iboot_in, pac);
    if (ret < 0)
        WARN("Error patching out RSA signature check\n");

    // 5. USB backdoor (install after all other patches)
    if (doUsbBackdoor) {
        LOG("Installing USB backdoor...\n");
        ret = install_usb_backdoor(&iboot_in);
        if (ret < 0)
            WARN("USB backdoor installation failed\n");
    }

    // Write output
    fp = fopen(outFile, "wb+");
    if (!fp) {
        printf("Error opening %s for writing\n", outFile);
        free(iboot_in.buf);
        return -1;
    }
    fwrite(iboot_in.buf, 1, iboot_in.len, fp);
    fflush(fp);
    fclose(fp);
    free(iboot_in.buf);
    LOG("Wrote patched image to %s\n", outFile);
    return 0;
}
