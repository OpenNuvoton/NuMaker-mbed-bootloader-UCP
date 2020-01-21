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

#ifndef MBEDBL_UCP_H
#define MBEDBL_UCP_H

#include <stdint.h>
#include "mbedtls/sha256.h"
#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* mbed-bootloader compatible UCP context for write */
typedef struct {
    uint32_t                    location;
    uint32_t                    offset;
    mbedtls_sha256_context      sha256_ctx;
    arm_uc_firmware_details_t   details;
    uint8_t                     fragment_unaligned[MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE];
    uint32_t                    fragment_unaligned_pos;
} mbedbl_ucp_wrtctx_t;

/* mbed-bootloader compatible UCP context for read */
typedef struct {
    uint32_t                    location;
    uint32_t                    offset;
    arm_uc_firmware_details_t   details;
    uint8_t                     fragment_unaligned[MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE];
    uint32_t                    fragment_unaligned_pos;
    uint32_t                    fragment_unaligned_size;
    mbedtls_sha256_context      sha256_ctx;
    uint16_t                    read_status;
} mbedbl_ucp_rdctx_t;

/** Prepare for writing a new firmware image to the specified location
 *
 * @param ucp_ctx           UCP context where to initialize for write below
 * @param location          Storage location where to write the new firmware image. Only 0 ~ (MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS - 1)
 * @param firmware_version  Firmware version. Must be UNIX timestamp in C-string format, like "1574817760".
 *                          Can acquire by running 'date +%s' on POSIX-like environment.
 * @param firmware_size     Firmware size in bytes
 * @return                  0 on success, -1 on failure
 */
int32_t MBEDBL_UCP_PrepareWrite(mbedbl_ucp_wrtctx_t *ucp_ctx, uint32_t location, const char *firmware_version, uint32_t firmware_size);

/** Write a firmware fragment
 *
 * @param ucp_ctx       UCP context initialized in MBEDBL_UCP_PrepareWrite
 * @param fragment      Fragment buffer,
 * @param fragment_size Fragment size in bytes on input, actually written size on output
 * @return              0 on success, otherwise -1 on failure
 *
 * @note                For performance, suggest fragment_size be MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE aligned (except the last write) to go direct write.
 * @note                On success, write will be complete, not partial. So the values held by fragment_size before/after this call will be the same.
 */
int32_t MBEDBL_UCP_Write(mbedbl_ucp_wrtctx_t *ucp_ctx, uint8_t *fragment, uint32_t *fragment_size);
                             
/** Commit to writing the firmware image
 *
 * @param ucp_ctx   UCP context initialized in MBEDBL_UCP_PrepareWrite
 * @return          0 on success, otherwise -1 on failure
 */
int32_t MBEDBL_UCP_FinalizeWrite(mbedbl_ucp_wrtctx_t *ucp_ctx);

/** Prepare for reading firmware from the specified location
 *
 * @param ucp_ctx           UCP context where to initialize for read below
 * @param location          Storage location where to read the new firmware image. Only 0 ~ (MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS - 1)
 * @return                  0 on success, -1 on failure
 */
int32_t MBEDBL_UCP_PrepareRead(mbedbl_ucp_rdctx_t *ucp_ctx, uint32_t location);

/** Read firmware fragment
 *
 * @param ucp_ctx               UCP context initialized in MBEDBL_UCP_PrepareRead
 * @param fragment              Fragment buffer
 * @param fragment_size         Fragment size in bytes on input, actually read size on output
 * @return                      0 on success, otherwise -1 on failure
 *
 * @note                        For performance, suggest fragment_size be MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE aligned (except the last read) to go direct read.
 */
int32_t MBEDBL_UCP_Read(mbedbl_ucp_rdctx_t *ucp_ctx, uint8_t *fragment, uint32_t *fragment_size);

/** Check if end of firmware data is reached
 *
 * @param ucp_ctx           UCP context initialized in MBEDBL_UCP_PrepareRead
 * @return                  1 on EOF, 0 on non-EOF, otherwise -1 on failure
 */
int32_t MBEDBL_UCP_Read_IsEof(mbedbl_ucp_rdctx_t *ucp_ctx);

/** Check if firmware is valid, after end of firmware data is reached
 *
 * @param ucp_ctx           UCP context initialized in MBEDBL_UCP_PrepareRead
 * @return                  1 on firmware valid, 0 on firmware invalid, otherwise -1 on failure, maybe not finished in reading firmware data
 */
int32_t MBEDBL_UCP_Read_IsFirmwareValid(mbedbl_ucp_rdctx_t *ucp_ctx, int32_t *firmware_valid);

/** Get firmware details from the specified location
 *
 * @param location          Storage location where to get the firmware details. Only 0 ~ (MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS - 1)
 * @param details           Firmware details struct where to populate on success, ignored on failure
 * @return                  0 on success, -1 on failure
 */
int32_t MBEDBL_UCP_GetFirmwareDetails(uint32_t location, arm_uc_firmware_details_t *details);

/** Check firmware validity for the specified location
 *
 * @param location          Storage location where to verify the firmware image. Only 0 ~ (MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS - 1)
 * @param temp_buffer       Temporary buffer for each UCP read
 * @param temp_buffer_size  Size of temporary buffer for each UCP read
 * @return                  1 on firmware valid, 0 on firmware invalid, otherwise -1 on failure
 */
int32_t MBEDBL_UCP_CheckFirmwareValidity(uint32_t location, uint8_t *temp_buffer, uint32_t temp_buffer_size);

/** Get firmware details for the actively running firmware
 *
 * @param details   Firmware details struct where to populate on success, ignored on failure
 * @return          0 on success, otherwise -1 on failure
 */
int32_t MBEDBL_UCP_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details);

#ifdef __cplusplus
}
#endif

#endif /* #if MBEDBL_UCP_H */
