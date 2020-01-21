/*
 * Copyright (c) 2019-2020, Nuvoton Technology Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include <stdlib.h>
#include "mbedbl-ucp.h"
#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"
#include "update-client-paal/arm_uc_paal_update.h"
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"
#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_platform.h"

#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

/* SHA-256 hash size in bytes*/
#define SIZEOF_SHA256  (256/8)

/* Flags for read status */
#define MBEDBL_UCP_READSTATUS_EOF           (1 << 0)    // End of firmware data
#define MBEDBL_UCP_READSTATUS_FIRMVFYED     (1 << 1)    // Firmware verfied
#define MBEDBL_UCP_READSTATUS_FIRMVALID     (1 << 2)    // Firmware valid, depends on firmware verified

/* Size in bytes of temporary buffer dynamically allocated for reading/verifying firmware */
#define TEMP_BUFFER_SIZE    2048

/* Indicate no UCP layer event */
#define CLEAR_EVENT 0xFFFFFFFF

#ifdef MBED_CLOUD_CLIENT_UPDATE_STORAGE
extern ARM_UC_PAAL_UPDATE MBED_CLOUD_CLIENT_UPDATE_STORAGE;
#else
#error Update client storage must be defined in user configuration file
#endif

/* Hold UCP layer event */
static uint32_t event_callback;

/* Initialize mbed-bootloader compatible UCP layer */
static int32_t MBEDBL_UCP_Initialize_(void);
/* Helper for UCP write aligned fragment data */
static int32_t UCP_Write_Aligned_(mbedbl_ucp_wrtctx_t *ucp_ctx, uint8_t *fragment_aligned, uint32_t *fragment_aligned_size);
/* Helper for UCP write unaligned fragment data */
static int32_t UCP_Write_Unaligned_(mbedbl_ucp_wrtctx_t *ucp_ctx);
/* Helper for UCP read aligned fragment data */
static int32_t UCP_Read_Aligned_(mbedbl_ucp_rdctx_t *ucp_ctx, uint8_t *fragment_aligned, uint32_t *fragment_aligned_size);
/* Helper for UCP read unaligned fragment data */
static int32_t UCP_Read_Unaligned_(mbedbl_ucp_rdctx_t *ucp_ctx);

/* Callback registered with UCP layer */
static void arm_ucp_event_handler(uint32_t event);

int32_t MBEDBL_UCP_PrepareWrite(mbedbl_ucp_wrtctx_t *ucp_ctx, uint32_t location, const char *firmware_version, uint32_t firmware_size)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null context */
        if (!ucp_ctx) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null UCP context");
            rc = -1;
            break;
        }

        /* Cannot exceed max storage locations */
        if (location >= ARM_UCP_GetMaxID()) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "%d exceeds max storage location id %d", location, ARM_UCP_GetMaxID() - 1);
            rc = -1;
            break;
        }

        /* Cannot be null firmware version */
        if (!firmware_version) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null firmware version");
            rc = -1;
            break;
        }

        /* Initialize context to zero */
        memset(ucp_ctx, 0x00, sizeof(*ucp_ctx));

        /* Populate storage location */
        ucp_ctx->location = location;

        /* Firmware version must be in UNIX timestamp format. Ex: "1574817760" by running 'date +%s' in POSIX-like environment. */
        char *firmware_version_end = NULL;
        uint64_t firmware_version_ = strtoull(firmware_version, &firmware_version_end, 10);
        if (!firmware_version_end || *firmware_version_end != '\0') {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Non-UNIX timestamp firmware version: %s", firmware_version);
            rc = -1;
            break;
        }
        /* Populate firmware version */
        ucp_ctx->details.version = firmware_version_;

        /* Populate firmware size */
        ucp_ctx->details.size = firmware_size;

        /* Support mbed-bootloader compatible UCP on cloud platforms with firmware hash not ready
         *
         * To be compatible with mbed-bootloader, firmware hash must be in SHA-256 and pass to ARM_UCP_Prepare(...).
         * Not all cloud platforms support this hash which is pre-calculated off-line and passed over the air. Instead,
         * we calculate this hash on-the-fly (with download process). For this support, we divide ARM_UCP_Prepare(...)
         * (underlying Prepare(...) implementations) into two modes:
         *
         * 1. Dummy hash mode: ARM_UCP_Prepare(...) runs as usual, but doesn't write firmware header to storage.
         *                     It is called in MBEDBL_UCP_PrepareWrite(...) when hash hasn't been ready.
         * 2. Valid hash mode: ARM_UCP_Prepare(...) only re-generates firmware header and writes it to storage.
         *                     It is called in MBEDBL_UCP_FinalizeWrite(...) when hash has calculated out.
         *
         * To distinguish the two modes, we use details.campaign, not used for non-Pelion, to pass necessary information
         * to ARM_UCP_Prepare(...), which runs in 'dummy hash' mode when details.campaign[0] == 0x00, otherwise 'valid hash'.
         */

        /* Specify firmware hash which is dummy */
        memset(ucp_ctx->details.hash, 0x00, ARM_UC_SHA256_SIZE);
        /* Notify ARM_UCP_Prepare(...) to run in 'dummy hash' mode */
        ucp_ctx->details.campaign[0] = 0x00;

        /* Initialize SHA-256 context */
        mbedtls_sha256_init(&ucp_ctx->sha256_ctx);
        /* Start SHA-256 checksum calculation */
        int mbedtls_status = mbedtls_sha256_starts_ret(&ucp_ctx->sha256_ctx, 0);
        if (mbedtls_status != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_starts_ret(...) failed with %d", mbedtls_status);
            rc = -1;
            break;
        }

        /* Clear most recent event */
        event_callback = CLEAR_EVENT;

        /* Prepare caller-allocated temporary buffer and format to ucp buffer */
        MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == 0);
        arm_uc_buffer_t ucp_buffer = {
            .size_max = MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE,
            .size     = 0,
            .ptr      = ucp_ctx->fragment_unaligned
        };

        /* Prepare UCP to receive new image, except write firmware header to storage due to dummy hash */
        arm_uc_error_t ucp_status = ARM_UCP_Prepare(ucp_ctx->location, &ucp_ctx->details, &ucp_buffer);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Prepare(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }
    } while (0);

    return rc;
}
                   
int32_t MBEDBL_UCP_Write(mbedbl_ucp_wrtctx_t *ucp_ctx, uint8_t *fragment, uint32_t *fragment_size)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null context */
        if (!ucp_ctx) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null UCP context");
            rc = -1;
            break;
        }

        /* Cannot be null fragment */
        if (!fragment) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null fragment");
            rc = -1;
            break;
        }

        /* Cannot be null fragment size */
        if (!fragment_size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null fragment size");
            rc = -1;
            break;
        }

        uint32_t fragment_rmn = *fragment_size;
        *fragment_size = 0;

        /* Unaligned address, not across aligned boundary (buffered write)
         *
         * Write to unaligned fragment buffer from source buffer
         * Then write to storage from unaligned fragment buffer if the buffer gets full (for aligned access).
         */
        if (fragment_rmn && ucp_ctx->fragment_unaligned_pos) {
            /* How many data to write? */
            uint32_t data_size = MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - ucp_ctx->fragment_unaligned_pos;
            if (data_size > fragment_rmn) {
                data_size = fragment_rmn;
            }

            /* Copy to temporary buffer for unaligned */
            memcpy(ucp_ctx->fragment_unaligned + ucp_ctx->fragment_unaligned_pos, fragment + *fragment_size, data_size);

            /* Advance for next write */
            ucp_ctx->fragment_unaligned_pos += data_size;
            *fragment_size += data_size;
            fragment_rmn -= data_size;

            /* Collect enough data to get aligned? */
            if (ucp_ctx->fragment_unaligned_pos == MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) {
                /* Get aligned, write it */
                rc = UCP_Write_Unaligned_(ucp_ctx);
                if (rc != 0) {
                    break;
                }
            }
        }

        /* Aligned address, aligned size (direct write)
         *
         * Write to storage from source buffer
         */
        if (fragment_rmn >= MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) {
            /* We shouldn't have unaligned data here. */
            MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == 0);

            /* Write aligned fragment data */            
            uint32_t data_size = fragment_rmn & ~(MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1);
            if (data_size) {
                rc = UCP_Write_Aligned_(ucp_ctx, fragment + *fragment_size, &data_size);
                if (rc != 0) {
                    break;
                }

                /* Advance for next write */
                *fragment_size += data_size;
                fragment_rmn -= data_size;
            }
        }

        /* Aligned address, unaligned size (buffered write)
         *
         * Write to unaligned fragment buffer from source buffer
         */
        if (fragment_rmn) {
            MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == 0);
            MBED_ASSERT(fragment_rmn < MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE);

            /* How many data to write */
            uint32_t data_size = fragment_rmn;
            
            /* Copy to unaligned fragment buffer */
            memcpy(ucp_ctx->fragment_unaligned + ucp_ctx->fragment_unaligned_pos, fragment + *fragment_size, data_size);

            /* Advance for next write */
            ucp_ctx->fragment_unaligned_pos += data_size;
            *fragment_size += data_size;
            fragment_rmn -= data_size;

            MBED_ASSERT(ucp_ctx->fragment_unaligned_pos < MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE);
        }
        
        MBED_ASSERT(fragment_rmn == 0);
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_FinalizeWrite(mbedbl_ucp_wrtctx_t *ucp_ctx)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null context */
        if (!ucp_ctx) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null UCP context");
            rc = -1;
            break;
        }

        /* Flush unaligned data */
        rc = UCP_Write_Unaligned_(ucp_ctx);
        if (rc != 0) {
            break;
        }

        /* Finish SHA-256 checksum calculation */
        int mbedtls_status = mbedtls_sha256_finish_ret(&ucp_ctx->sha256_ctx, ucp_ctx->details.hash);
        if (mbedtls_status != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_finish_ret(...) failed with %d", mbedtls_status);
            rc = -1;
            break;
        }

        /* Match firmware size? */
        if (ucp_ctx->offset != ucp_ctx->details.size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Write firmware size expected %d but actual %d", (uint32_t) ucp_ctx->details.size, ucp_ctx->offset);
            rc = -1;
            break;
        }

        /* Notify ARM_UCP_Prepare(...) to run in 'valid hash' mode */
        ucp_ctx->details.campaign[0] = 0xff;

        /* Prepare caller-allocated temporary buffer and format to ucp buffer */
        MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == 0);
        arm_uc_buffer_t ucp_buffer = {
            .size_max = MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE,
            .size     = 0,
            .ptr      = ucp_ctx->fragment_unaligned
        };

        /* Only re-generate firmware header and write to storage due to valid hash */
        arm_uc_error_t ucp_status = ARM_UCP_Prepare(ucp_ctx->location, &ucp_ctx->details, &ucp_buffer);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Prepare(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }

        /* Finalize UCP write */
        ucp_status = ARM_UCP_Finalize(ucp_ctx->location);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Finalize(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_PrepareRead(mbedbl_ucp_rdctx_t *ucp_ctx, uint32_t location)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null context */
        if (!ucp_ctx) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null UCP context");
            rc = -1;
            break;
        }

        /* Cannot exceed max storage locations */
        if (location >= ARM_UCP_GetMaxID()) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "%d exceeds max storage location id %d", location, ARM_UCP_GetMaxID() - 1);
            rc = -1;
            break;
        }

        /* Initialize context to zero */
        memset(ucp_ctx, 0x00, sizeof(*ucp_ctx));

        /* Populate storage location */
        ucp_ctx->location = location;

        /* Clear most recent event */
        event_callback = CLEAR_EVENT;

        /* Fetch firmware detail from storage */
        arm_uc_error_t ucp_status = ARM_UCP_GetFirmwareDetails(ucp_ctx->location, &ucp_ctx->details);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_GetFirmwareDetails(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }

        /* Initialize SHA-256 context */
        mbedtls_sha256_init(&ucp_ctx->sha256_ctx);
        /* Start SHA-256 checksum calculation */
        int mbedtls_status = mbedtls_sha256_starts_ret(&ucp_ctx->sha256_ctx, 0);
        if (mbedtls_status != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_starts_ret(...) failed with %d", mbedtls_status);
            rc = -1;
            break;
        }
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_Read(mbedbl_ucp_rdctx_t *ucp_ctx, uint8_t *fragment, uint32_t *fragment_size)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null context */
        if (!ucp_ctx) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null UCP context");
            rc = -1;
            break;
        }

        /* Cannot be null fragment buffer */
        if (!fragment) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null fragment buffer");
            rc = -1;
            break;
        }

        /* Cannot be null fragment buffer size */
        if (!fragment_size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null fragment buffer size");
            rc = -1;
            break;
        }

        /* We have finished reading firmware data? */
        if (ucp_ctx->read_status & MBEDBL_UCP_READSTATUS_EOF) {
            *fragment_size = 0;
            break;
        }

        uint32_t fragment_rmn = *fragment_size;
        *fragment_size = 0;

        /* Unaligned address, not across aligned boundary (buffered read)
         *
         * Read from unaligned fragment buffer to destination buffer
         */
        if (fragment_rmn && (ucp_ctx->fragment_unaligned_pos < ucp_ctx->fragment_unaligned_size)) {
            /* How many data to read? */
            uint32_t data_size = ucp_ctx->fragment_unaligned_size - ucp_ctx->fragment_unaligned_pos;
            if (data_size > fragment_rmn) {
                data_size = fragment_rmn;
            }

            /* Copy to destination buffer from unaligned fragment buffer */
            memcpy(fragment + *fragment_size, ucp_ctx->fragment_unaligned + ucp_ctx->fragment_unaligned_pos, data_size);

            /* Advance for next read */
            ucp_ctx->fragment_unaligned_pos += data_size;
            *fragment_size += data_size;
            fragment_rmn -= data_size;
        }

        /* Aligned address, aligned size (direct read)
         *
         * Read from storage to destination buffer
         */
        if (fragment_rmn >= MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) {
            /* We shouldn't have unaligned data here. */
            MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == ucp_ctx->fragment_unaligned_size);

            /* Read aligned fragment data */            
            uint32_t data_size = fragment_rmn & ~(MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1);
            if (data_size) {
                rc = UCP_Read_Aligned_(ucp_ctx, fragment + *fragment_size, &data_size);
                if (rc != 0) {
                    break;
                }

                /* Advance for next read */
                *fragment_size += data_size;
                fragment_rmn -= data_size;
            }
        }

        /* Aligned address, unaligned size (direct read)
         *
         * Read from storage to unaligned fragment buffer (for aligned access)
         * Then read from unaligned fragment buffer to destination buffer
         */
        if (fragment_rmn) {
            MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == ucp_ctx->fragment_unaligned_size);

            /* Buffer for unaligned read */
            rc = UCP_Read_Unaligned_(ucp_ctx);
            if (rc != 0) {
                break;
            }

            /* How many data to read */
            uint32_t data_size = ucp_ctx->fragment_unaligned_size - ucp_ctx->fragment_unaligned_pos;
            if (data_size > fragment_rmn) {
                data_size = fragment_rmn;
            }

            /* Copy from unaligned fragment buffer */
            memcpy(fragment + *fragment_size, ucp_ctx->fragment_unaligned + ucp_ctx->fragment_unaligned_pos, data_size);

            /* Advance for next read */
            ucp_ctx->fragment_unaligned_pos += data_size;
            *fragment_size += data_size;
            fragment_rmn -= data_size;
        }

        /* We have finished reading firmware data? */
        if (ucp_ctx->offset == ucp_ctx->details.size &&
            (ucp_ctx->fragment_unaligned_pos == ucp_ctx->fragment_unaligned_size)) {
            ucp_ctx->read_status |= MBEDBL_UCP_READSTATUS_EOF;
        }

        /* Verify firmware data when finished reading from storage and not verified yet */
        if (ucp_ctx->offset == ucp_ctx->details.size &&
            !(ucp_ctx->read_status & MBEDBL_UCP_READSTATUS_FIRMVFYED)) {
            /* Finish SHA-256 checksum calculation */
            unsigned char sha256_hash[SIZEOF_SHA256];
            int mbedtls_status = mbedtls_sha256_finish_ret(&ucp_ctx->sha256_ctx, &sha256_hash[0]);
            if (mbedtls_status != 0) {
                ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_finish_ret(...) failed with %d", mbedtls_status);
                rc = -1;
                break;
            }

            /* Compare hash value */
            if (memcmp(sha256_hash, ucp_ctx->details.hash, SIZEOF_SHA256) == 0) {
                ucp_ctx->read_status |= (MBEDBL_UCP_READSTATUS_FIRMVFYED | MBEDBL_UCP_READSTATUS_FIRMVALID);
            } else {
                ucp_ctx->read_status |= MBEDBL_UCP_READSTATUS_FIRMVFYED;
            }
        }
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_Read_IsEof(mbedbl_ucp_rdctx_t *ucp_ctx)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null context */
        if (!ucp_ctx) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null UCP context");
            rc = -1;
            break;
        }

        /* Return EOF flag */
        rc = !!(ucp_ctx->read_status & MBEDBL_UCP_READSTATUS_EOF);
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_Read_IsFirmwareValid(mbedbl_ucp_rdctx_t *ucp_ctx)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null context */
        if (!ucp_ctx) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null UCP context");
            rc = -1;
            break;
        }

        /* We must have verified firmware data, including finished reading firmware data */
        if (!(ucp_ctx->read_status & MBEDBL_UCP_READSTATUS_FIRMVFYED)) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Firmware data not verifed yet, possibly due to not finished reading!");
            rc = -1;
            break;
        }

        /* Return firmware valid flag */
        rc = !!(ucp_ctx->read_status & MBEDBL_UCP_READSTATUS_FIRMVALID);
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_GetFirmwareDetails(uint32_t location, arm_uc_firmware_details_t *details)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot exceed max storage locations */
        if (location >= ARM_UCP_GetMaxID()) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "%d exceeds max storage location id %d", location, ARM_UCP_GetMaxID() - 1);
            rc = -1;
            break;
        }

        if (!details) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null firmware details");
            rc = -1;
            break;
        }

        /* Prepare for read */
        mbedbl_ucp_rdctx_t ucp_ctx;
        rc = MBEDBL_UCP_PrepareRead(&ucp_ctx, location);
        if (rc != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "MBEDBL_UCP_PrepareRead(...) failed with %d", rc);
            break;
        }

        /* Return firmware details */
        memcpy(details, &ucp_ctx.details, sizeof(*details));
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_CheckFirmwareValidity(uint32_t location, uint8_t *temp_buffer, uint32_t temp_buffer_size)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Prepare for UCP read */
        mbedbl_ucp_rdctx_t ucp_ctx;
        rc = MBEDBL_UCP_PrepareRead(&ucp_ctx, location);
        if (rc != 0) {
            break;
        }

        /* Cannot be null temporary buffer */
        if (!temp_buffer) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null temporary buffer");
            rc = -1;
            break;
        }

        /* Cannot be zero temporary buffer size */
        if (temp_buffer_size == 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Zero temporary buffer size");
            rc = -1;
            break;
        }

        /* Read and discard until EOF */
        while (true) {
            /* Reach EOF? */
            rc = MBEDBL_UCP_Read_IsEof(&ucp_ctx);
            if (rc == 1) {
                rc = 0;
                break;
            } else if (rc == 0) {
                /* Do read below */
            } else {
                ARM_UC_TRACE_ERROR_PRINTF("BLUC", "MBEDBL_UCP_Read_IsEof(...) failed with %d", rc);
                break;
            }

            /* Read and discard */
            uint32_t size = temp_buffer_size;
            rc = MBEDBL_UCP_Read(&ucp_ctx, temp_buffer, &size);
            if (rc != 0) {
                ARM_UC_TRACE_ERROR_PRINTF("BLUC", "MBEDBL_UCP_Read(...) failed with %d", rc);
                break;
            }
        }
        if (rc != 0) {
            break;
        }

        /* Check firmware validity */
        rc = MBEDBL_UCP_Read_IsFirmwareValid(&ucp_ctx);
        if (rc < 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "MBEDBL_UCP_Read_IsFirmwareValid(...) failed with %d", rc);
            break;
        }
    } while (0);

    return rc;
}

int32_t MBEDBL_UCP_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details)
{
    int rc = 0;

    do {
        /* Initialize mbed-bootloader compatible UCP layer */
        if (MBEDBL_UCP_Initialize_() != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Initialize mbed-bootloader compatible UCP layer failed");
            rc = -1;
            break;
        }

        /* Cannot be null details */
        if (!details) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Null details");
            rc = -1;
            break;
        }

        /* Clear most recent event */
        event_callback = CLEAR_EVENT;

        /* Fetch active firmware details from storage */
        arm_uc_error_t ucp_status = ARM_UCP_GetActiveFirmwareDetails(details);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_GetActiveFirmwareDetails(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }
    } while (0);

    return rc;
}

static int32_t MBEDBL_UCP_Initialize_(void)
{
    static int16_t inited_ = 0;

    /* mbed-bootloader compatible UCP layer has initialied? */
    if (inited_) {
        return 0;
    }

    /* Set PAAL Update implementation before initializing Firmware Manager */
    ARM_UCP_SetPAALUpdate(&MBED_CLOUD_CLIENT_UPDATE_STORAGE);

    /* Initialize PAL */
    arm_uc_error_t ucp_result = ARM_UCP_Initialize(arm_ucp_event_handler);
    if (ucp_result.error != ERR_NONE) {
        ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Initialize failed with %d", ucp_result.error);
        return -1;
    }

    /* Unaligned fragment buffer is flashiap page aligned? */
    if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE & (arm_uc_flashiap_get_page_size() - 1)) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_UNKNOWN, MBED_ERROR_CODE_UNKNOWN), \
                   "MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE(" STR(MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) ") not aligned to flashiap page size");
    }

    /* Unaligned fragment buffer is blockdevice program size aligned? */
    if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE & (arm_uc_blockdevice_get_program_size() -1)) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_UNKNOWN, MBED_ERROR_CODE_UNKNOWN), \
                   "MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE(" STR(MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) ") not aligned to block device program size");
    }

    /* Unaligned fragment buffer is enough for creating internal header temporarity?*/
    if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE < ARM_UC_INTERNAL_HEADER_SIZE_V2) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_UNKNOWN, MBED_ERROR_CODE_UNKNOWN), \
                   "MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE(" STR(MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) ") must be at least ARM_UC_INTERNAL_HEADER_SIZE_V2(" STR(ARM_UC_INTERNAL_HEADER_SIZE_V2) ") for temporary buffer usage!");
    }

    /* Unaligned fragment buffer is enough for creating external header temporarity?*/
    if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE < ARM_UC_EXTERNAL_HEADER_SIZE_V2) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_UNKNOWN, MBED_ERROR_CODE_UNKNOWN), \
                   "MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE(" STR(MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) ") must be at least ARM_UC_EXTERNAL_HEADER_SIZE_V2(" STR(ARM_UC_EXTERNAL_HEADER_SIZE_V2) ") for temporary buffer usage!");
    }

    /* Mark mbed-bootloader compatible UCP layer has initialied */
    inited_ = 1;

    return 0;
}

static int32_t UCP_Write_Aligned_(mbedbl_ucp_wrtctx_t *ucp_ctx, uint8_t *fragment_aligned, uint32_t *fragment_aligned_size)
{
    MBED_ASSERT(ucp_ctx != NULL);
    MBED_ASSERT(fragment_aligned != NULL);
    MBED_ASSERT(fragment_aligned_size != NULL);
    MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == 0);

    int rc = 0;

    do {
        /* Write no data? */
        if (*fragment_aligned_size == 0) {
            break;
        }

        /* How many data to write? */
        uint32_t data_size = *fragment_aligned_size;
        if ((ucp_ctx->offset + data_size) > ucp_ctx->details.size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Write beyond firmware payload size, CUR=0x%08x, WRT=0x%08x, TOT=0x%08x", (uint32_t) ucp_ctx->offset, data_size, (uint32_t) ucp_ctx->details.size);
            rc = -1;
            break;
        }

        /* Guard from false success returned by UCP layer
         *
         * UCP layer may return false success in the following cases. We should have got around them:
         * - Zero access size
         * - Unaligned access
         * - Access beyond firmware payload size
         */
        MBED_ASSERT(data_size);
        MBED_ASSERT((ucp_ctx->offset & (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)) == 0);
        MBED_ASSERT((ucp_ctx->offset + data_size) <= ucp_ctx->details.size);

        /* Reset actually write size */
        *fragment_aligned_size = 0;

        /* Clear most recent event */
        event_callback = CLEAR_EVENT;

        /* Format to ucp buffer */
        arm_uc_buffer_t ucp_buffer = {
            .size_max = data_size,
            .size     = data_size,
            .ptr      = fragment_aligned
        };

        /* UCP write to storage */
        arm_uc_error_t ucp_status = ARM_UCP_Write(ucp_ctx->location, ucp_ctx->offset, &ucp_buffer);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Write(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }

        /* Check if ARM_UCP_Write(...) writes completely on success */
        if (ucp_buffer.size != data_size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Write(...) failed. Expected %d but actual %d", data_size, ucp_buffer.size);
            rc = -1;
            break;
        }

        /* Calculate firmware hash */
        int mbedtls_status = mbedtls_sha256_update_ret(&ucp_ctx->sha256_ctx, fragment_aligned, ucp_buffer.size);
        if (mbedtls_status != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_update_ret(...) failed with %d", mbedtls_status);
            rc = -1;
            break;
        }

        /* Advance for next UCP write */
        ucp_ctx->offset += ucp_buffer.size;

        /* Return actually write size */
        *fragment_aligned_size += ucp_buffer.size;
    } while (0);

    return rc;
}

static int32_t UCP_Write_Unaligned_(mbedbl_ucp_wrtctx_t *ucp_ctx)
{
    MBED_ASSERT(ucp_ctx != NULL);
    MBED_ASSERT(ucp_ctx->fragment_unaligned_pos <= MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE);

    int rc = 0;

    do {
        /* Write no data? */
        if (ucp_ctx->fragment_unaligned_pos == 0) {
            break;
        }

        /* How many data to write? */
        uint32_t data_size = ucp_ctx->fragment_unaligned_pos;
        if ((ucp_ctx->offset + data_size) > ucp_ctx->details.size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "Write beyond firmware payload size, CUR=0x%08x, WRT=0x%08x, TOT=0x%08x", (uint32_t) ucp_ctx->offset, data_size, (uint32_t) ucp_ctx->details.size);
            rc = -1;
            break;
        }

        /* Guard from false success returned by UCP layer
         *
         * UCP layer may return false success in the following cases. We should have got around them:
         * - Zero access size
         * - Unaligned access
         * - Access beyond firmware payload size
         */
        MBED_ASSERT(data_size);
        MBED_ASSERT((ucp_ctx->offset & (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)) == 0);
        MBED_ASSERT((ucp_ctx->offset + data_size) <= ucp_ctx->details.size);

        /* Clear most recent event */
        event_callback = CLEAR_EVENT;

        /* Format to ucp buffer */
        arm_uc_buffer_t ucp_buffer = {
            .size_max = MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE,
            .size     = data_size,
            .ptr      = ucp_ctx->fragment_unaligned
        };

        /* UCP write to storage */
        arm_uc_error_t ucp_status = ARM_UCP_Write(ucp_ctx->location, ucp_ctx->offset, &ucp_buffer);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Write(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }

        /* Check if ARM_UCP_Write(...) writes completely on success */
        if (ucp_buffer.size != data_size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Write(...) failed. Expected %d but actual %d", data_size, ucp_buffer.size);
            rc = -1;
            break;
        }

        /* Calculate firmware hash */
        int mbedtls_status = mbedtls_sha256_update_ret(&ucp_ctx->sha256_ctx, ucp_buffer.ptr, ucp_buffer.size);
        if (mbedtls_status != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_update_ret(...) failed with %d", mbedtls_status);
            rc = -1;
            break;
        }

        /* Advance for next UCP write */
        ucp_ctx->offset += ucp_buffer.size;

        /* Reset unaligned position */
        ucp_ctx->fragment_unaligned_pos = 0;
    } while (0);

    return rc;
}

static int32_t UCP_Read_Aligned_(mbedbl_ucp_rdctx_t *ucp_ctx, uint8_t *fragment_aligned, uint32_t *fragment_aligned_size)
{
    MBED_ASSERT(ucp_ctx != NULL);
    MBED_ASSERT(fragment_aligned != NULL);
    MBED_ASSERT(fragment_aligned_size != NULL);
    MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == ucp_ctx->fragment_unaligned_size);

    int rc = 0;

    do {
        /* Read no data? */
        if (*fragment_aligned_size == 0) {
            break;
        }

        /* How many data to read? */
        uint32_t data_size = *fragment_aligned_size;
        if ((ucp_ctx->offset + data_size) > ucp_ctx->details.size) {
            data_size = (ucp_ctx->details.size - ucp_ctx->offset) & ~(MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1);
        }
        if (data_size == 0) {
            *fragment_aligned_size = 0;
            break;
        }

        /* Guard from false success returned by UCP layer
         *
         * UCP layer may return false success in the following cases. We should have got around them:
         * - Zero access size
         * - Unaligned access
         * - Access beyond firmware payload size
         */
        MBED_ASSERT(data_size);
        MBED_ASSERT((ucp_ctx->offset & (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)) == 0);
        MBED_ASSERT((ucp_ctx->offset + data_size) <= ucp_ctx->details.size);

        /* Reset actually read size */
        *fragment_aligned_size = 0;

        /* Clear most recent event */
        event_callback = CLEAR_EVENT;

        /* Format to ucp buffer */
        arm_uc_buffer_t ucp_buffer = {
            .size_max = data_size,
            .size     = data_size,
            .ptr      = fragment_aligned
        };

        /* UCP read from storage */
        arm_uc_error_t ucp_status = ARM_UCP_Read(ucp_ctx->location, ucp_ctx->offset, &ucp_buffer);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Read(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }

        /* Check if ARM_UCP_Read(...) reads completely on success */
        if (ucp_buffer.size != data_size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Read(...) failed. Expected %d but actual %d", data_size, ucp_buffer.size);
            rc = -1;
            break;
        }

        /* Calculate firmware hash */
        int mbedtls_status = mbedtls_sha256_update_ret(&ucp_ctx->sha256_ctx, fragment_aligned, ucp_buffer.size);
        if (mbedtls_status != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_update_ret(...) failed with %d", mbedtls_status);
            rc = -1;
            break;
        }

        /* Advance for next UCP read */
        ucp_ctx->offset += ucp_buffer.size;

        /* Return actually read size */
        *fragment_aligned_size += ucp_buffer.size;
    } while (0);

    return rc;
}

static int32_t UCP_Read_Unaligned_(mbedbl_ucp_rdctx_t *ucp_ctx)
{
    MBED_ASSERT(ucp_ctx != NULL);
    MBED_ASSERT(ucp_ctx->fragment_unaligned_pos == ucp_ctx->fragment_unaligned_size);

    int rc = 0;

    do {
        /* How many data to read? */
        uint32_t data_size = MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE;
        if ((ucp_ctx->offset + data_size) > ucp_ctx->details.size) {
            data_size = ucp_ctx->details.size - ucp_ctx->offset;
        }
        if (data_size == 0) {
            break;
        }

        /* Guard from false success returned by UCP layer
         *
         * UCP layer may return false success in the following cases. We should have got around them:
         * - Zero access size
         * - Unaligned access
         * - Access beyond firmware payload size
         */
        MBED_ASSERT(data_size);
        MBED_ASSERT((ucp_ctx->offset & (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)) == 0);
        MBED_ASSERT((ucp_ctx->offset + data_size) <= ucp_ctx->details.size);

        /* Reset unaligned position/size */
        ucp_ctx->fragment_unaligned_pos = 0;
        ucp_ctx->fragment_unaligned_size = 0;
        
        /* Clear most recent event */
        event_callback = CLEAR_EVENT;

        /* Format to ucp buffer */
        arm_uc_buffer_t ucp_buffer = {
            .size_max = MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE,
            .size     = data_size,
            .ptr      = ucp_ctx->fragment_unaligned
        };

        /* UCP read from storage */
        arm_uc_error_t ucp_status = ARM_UCP_Read(ucp_ctx->location, ucp_ctx->offset, &ucp_buffer);
        /* Wait for event if call was accepted */
        if (ucp_status.error == ERR_NONE) {
            while (event_callback == CLEAR_EVENT) {
                __WFI();
            }
        } else {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Read(...) failed with %d", ucp_status.error);
            rc = -1;
            break;
        }

        /* Check if ARM_UCP_Read(...) reads completely on success */
        if (ucp_buffer.size != data_size) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "ARM_UCP_Read(...) failed. Expected %d but actual %d", data_size, ucp_buffer.size);
            rc = -1;
            break;
        }

        /* Calculate firmware hash */
        int mbedtls_status = mbedtls_sha256_update_ret(&ucp_ctx->sha256_ctx, ucp_buffer.ptr, ucp_buffer.size);
        if (mbedtls_status != 0) {
            ARM_UC_TRACE_ERROR_PRINTF("BLUC", "mbedtls_sha256_update_ret(...) failed with %d", mbedtls_status);
            rc = -1;
            break;
        }

        /* Advance for next UCP read */
        ucp_ctx->offset += ucp_buffer.size;

        /* Mark having unaligned fragment data */
        ucp_ctx->fragment_unaligned_size = ucp_buffer.size;
    } while (0);

    return rc;
}

static void arm_ucp_event_handler(uint32_t event)
{
    event_callback = event;
}
