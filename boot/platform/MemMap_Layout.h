/**
 * @file    MemMap_Layout.h
 * @brief   Host flash memory map of the simulated ECU.
 *
 *  0x00000 +----------------------+
 *          | Boot Manager  (16K)  |  \  protected by HSM secure boot
 *  0x04000 +----------------------+   > (SHE BOOT_MAC over BM + BL)
 *          | Bootloader    (48K)  |  /
 *  0x10000 +----------------------+
 *          | App header   (128 B) |  \  verified by Boot Manager via CSM
 *          | Application  (~192K) |  /  (SHA-256 + CMAC, anti roll-back)
 *  0x40000 +----------------------+
 *          | Boot data flash (4K) |  programming request flag etc.
 *  0x41000 +----------------------+
 */
#ifndef MEMMAP_LAYOUT_H
#define MEMMAP_LAYOUT_H

#define FLS_SECTOR_SIZE         0x1000u
#define FLS_TOTAL_SIZE          0x41000u
#define FLS_ERASED_VALUE        0xFFu

#define BM_START                0x00000u
#define BM_SIZE                 0x04000u
#define BL_START                0x04000u
#define BL_SIZE                 0x0C000u
#define SECURE_BOOT_START       BM_START
#define SECURE_BOOT_SIZE        (BM_SIZE + BL_SIZE)

#define APP_START               0x10000u
#define APP_SIZE                0x30000u
#define APP_HEADER_SIZE         0x80u
#define APP_BODY_START          (APP_START + APP_HEADER_SIZE)
#define APP_BODY_MAX            (APP_SIZE - APP_HEADER_SIZE)

#define BOOTDATA_START          0x40000u
#define BOOTDATA_SIZE           0x01000u

#endif
