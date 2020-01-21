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
#include "mbedbl-ucp.h"
#include "wrappers.h"
#include <inttypes.h>

arm_uc_firmware_details_t active_firmware_details;
arm_uc_firmware_details_t update_firmware_details;
char active_firmware_version_buffer[30] = { 0 };

static int initialization_test(void);
static int write_verify_by_fragment_n_test(uint32_t location, uint32_t fragment_size);

int main()
{
    int rc = 0;
    uint32_t fragment_size;

    printf("\r\nmbed-bootloader compatible firmware update test...\r\n\r\n");

    do {
        /* Initialization test */
        rc = initialization_test();
        if (rc != 0) {
            printf("initialization_test() failed with %d\r\n", rc);
            break;
        }

        /* In the following, we use active firmware as source for testing mbed-bootloader compatible UCP */
        /* Write to location 0 by different fragment sizes */
        uint32_t fragment_size_array[] = {256, 512, 768, 1024, 1280, 1536, 1792, 2048, 2304, 111, 333, 555, 777, 999, 1111, 3333, 1357};
        uint32_t *fragment_size_ind = fragment_size_array;
        uint32_t *fragment_size_end = fragment_size_array + sizeof(fragment_size_array)/sizeof(fragment_size_array[0]);
        for (; fragment_size_ind != fragment_size_end; fragment_size_ind ++) {
            rc = write_verify_by_fragment_n_test(0, *fragment_size_ind);
            if (rc != 0) {
                break;
            }
        }
    } while (0);

    if (rc == 0) {
        printf("nmbed-bootloader compatible firmware update test...OK\r\n\r\n");
    } else {
        printf("nmbed-bootloader compatible firmware update test...FAILED\r\n\r\n");
    }

    return rc;
}

static int initialization_test(void)
{
    int32_t rc = 0;

    do {
        /* Layout information */
        printf("APPLICATION_ADDR: %08x\r\n", APPLICATION_ADDR);
        printf("update-client.application-details: 0x%08x\r\n", MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS);
        printf("update-client.storage-address: 0x%08x\r\n", MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS);
        printf("update-client.storage-size: 0x%08x\r\n", MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE);
        printf("update-client.storage-locations: %d\r\n", MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS);
        printf("update-client.storage-page: %d\r\n", MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE);

        /* Print information of mbed-bootloader compatible UCP */
        printf("sizeof(mbedbl_ucp_wrtctx_t): %d bytes\r\n", sizeof(mbedbl_ucp_wrtctx_t));
        printf("sizeof(mbedbl_ucp_rdctx_t): %d bytes\r\n", sizeof(mbedbl_ucp_rdctx_t));

        /* Get active firmware version via mbed-bootloader compatible UCP */
        rc = MBEDBL_UCP_GetActiveFirmwareDetails(&active_firmware_details);
        if (rc != 0) {
            printf("MBEDBL_UCP_GetActiveFirmwareDetails() failed with %d\r\n", rc);
        }
        int cx = snprintf(active_firmware_version_buffer, sizeof(active_firmware_version_buffer), "%" PRId64, active_firmware_details.version);
        if (cx < 0 || cx >= sizeof(active_firmware_version_buffer)) {
            printf("snprintf(%d) failed with %d\r\n", sizeof(active_firmware_version_buffer), cx);
            rc = -1;
            break;
       }
        printf("Active firmware version via MBEDBL_UCP_GetActiveFirmwareDetails(...): %s\r\n", active_firmware_version_buffer);

        /* Get active firmware version via aliyun device SDK API */
        char alihal_firmware_version_buffer[IOTX_FIRMWARE_VER_LEN + 1];
        int alihal_rc = HAL_GetFirmwareVersion(alihal_firmware_version_buffer);
        if (alihal_rc < 0) {
            rc = -1;
            printf("HAL_GetFirmwareVersion(...) failed with %d\r\n", alihal_rc);
            break;
        }
        printf("Active firmware version via HAL_GetFirmwareVersion(...): %s\r\n", alihal_firmware_version_buffer);

        /* Two version values the same? */
        if (strcmp(active_firmware_version_buffer, alihal_firmware_version_buffer) != 0) {
            rc = -1;
            printf("The above two firmware version values must equal\r\n");
            break;
        }
    } while (0);

    printf("\r\n");

    return rc;
}

static int write_verify_by_fragment_n_test(uint32_t location, uint32_t fragment_size)
{
    int32_t rc = 0;
    char firmware_version_buffer[30] = { 0 };
    uint8_t *temp_buffer = NULL;

    /* Start of write/verify firmware */
    printf("write_verify_by_fragment_n_test(%d, %d)...\r\n", location, fragment_size);

    do {
        /* Prepare UCP write */
        mbedbl_ucp_wrtctx_t ucp_ctx;
        rc = MBEDBL_UCP_PrepareWrite(&ucp_ctx, location, active_firmware_version_buffer, (uint32_t) active_firmware_details.size);
        if (rc != 0) {
            break;
        }

        uint8_t *firmware_ind = (uint8_t *) APPLICATION_ADDR;
        uint8_t *firmware_end = (uint8_t *) APPLICATION_ADDR + ((uint32_t) active_firmware_details.size);
        while (firmware_ind < firmware_end) {
            /* Limit fragment size to indicated */
            uint32_t fragment_size_ = firmware_end - firmware_ind;
            if (fragment_size_ > fragment_size) {
                fragment_size_ = fragment_size;
            }

            /* UCP write a fragment */
            rc = MBEDBL_UCP_Write(&ucp_ctx, firmware_ind, &fragment_size_);
            if (rc != 0) {
                break;
            }

            /* Advance for next UCP write */
            firmware_ind += fragment_size_;
        }

        /* Finalize UCP write */
        rc = MBEDBL_UCP_FinalizeWrite(&ucp_ctx);
        if (rc != 0) {
            break;
        }

        /* Get update firmware details written just now */
        rc = MBEDBL_UCP_GetFirmwareDetails(location, &update_firmware_details);
        if (rc != 0) {
            break;
        }

        /* Get active firmware details */
        rc = MBEDBL_UCP_GetActiveFirmwareDetails(&active_firmware_details);
        if (rc != 0) {
            break;
        }

        /* Compare hash code of update/active firmware */
        if (memcmp(update_firmware_details.hash, active_firmware_details.hash, ARM_UC_SHA256_SIZE) != 0) {
            printf("Firmware hash mismatched between update/active firmware\r\n");
            rc = -1;
            break;
        }

        temp_buffer = new uint8_t[fragment_size];

        /* Read/verify firmware via MBEDBL_UCP_CheckFirmwareValidity(...) */
        rc = MBEDBL_UCP_CheckFirmwareValidity(location, temp_buffer, fragment_size);
        if (rc == 1) {
            rc = 0;
        } else if (rc == 0) {
            printf("Update firmware INVALID\r\n");
        } else {
            break;
        }
    } while (0);

    /* Release temporary buffer */
    delete [] temp_buffer;

    /* End of write/verify firmware */
    printf("write_verify_by_fragment_n_test(%d, %d)...%s\r\n\r\n", location, fragment_size, (rc == 0) ? "OK" : "FAILED");

    return rc;
}

static int verify_by_fragment_n_test(uint32_t location, uint32_t fragment_size)
{
    int rc = 0;
    uint8_t *temp_buffer = NULL;
    bool firmware_valid = false;

    /* Start of read/verify firmware */
    printf("verify_by_fragment_n_test(%d, %d)...\r\n", location, fragment_size);

    temp_buffer = new uint8_t[fragment_size];

    /* Read/verify firmware via MBEDBL_UCP_CheckFirmwareValidity(...) */
    rc = MBEDBL_UCP_CheckFirmwareValidity(location, temp_buffer, fragment_size);
    if (rc == 1) {
        firmware_valid = true;
        rc = 0;
    } else if (rc == 0) {
        firmware_valid = false;
    } else {
        printf("MBEDBL_UCP_CheckFirmwareValidity failed with %d\r\n", rc);
    }

    /* Release temporary buffer */
    delete [] temp_buffer;

    /* End of read/verify firmware */
    if (rc == 0) {
        printf("verify_by_fragment_n_test(%d, %d)...OK. Firmware %s\r\n", location, fragment_size, firmware_valid ? "VALID" : "INVALID");
    } else {
        printf("verify_by_fragment_n_test(%d, %d)...FAILED\r\n", location, fragment_size);
    }

    return rc;
}
