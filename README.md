# Library for mbed-bootloader compatible firmware update

On Mbed OS, Arm designs [mbed-bootloader](https://github.com/ARMmbed/mbed-bootloader) to be used in conjunction with [Pelion Device Management Client](https://github.com/ARMmbed/mbed-cloud-client) for firmware Over-The-Air (OTA).
However, thanks to it being generic, it is possible for mbed-bootloader to be used with other non-Pelion firmware OTA cases.
For this goal, downloaded firmware must write to storage in a format compatible with mbed-bootloader.
This is why the library is created.

## Design guide

In fact, mbed-bootloader has abstracted [UCP module](https://github.com/ARMmbed/mbed-bootloader/tree/master/modules) from [Pelion Device Management Client library](https://github.com/ARMmbed/mbed-cloud-client) for compatible firmware write/validation.
The library here also integrates the UCP module and makes adaptation to fit non-Pelion firmware OTA cases.
On top of the UCP module, the library opens `MBEDBL_UCP` API for writing/validating downloaded firmware.

### Calculate SHA-256 firmware hash code on-the-fly

mbed-bootloader checks firmware integrity by SHA-256.
However, not all firmware OTA provide SHA-256 in their protocol, maybe by another hash algorithm.
To cover this case, SHA-256 is calculated on-the-fly in download/write process.
To support this, the API `ARM_UCP_Prepare(...)` in the UCP module is divided to two modes:

-   Dummy hash mode: `ARM_UCP_Prepare(...)` runs as usual but doesn't write firmware header to storage. This mode is run for preparing UCP write.
-   Valid hash mode: `ARM_UCP_Prepare(...)` only re-generates firmware header and writes it to storage. This mode is run for committing UCP write.

### Guarantee page aligned access to storage by buffering

Access to storage usually must be in blocks.
However, downloaded firmware fragment size usually isn't block-aligned.
To cover this unaligned access, access to storage is buffered in page, which must be block-aligned and 2 to the nth power. By default, it is 512 bytes. 

### Use UNIX timestamp as firmware version

mbed-bootloader uses [UNIX timestamp](https://en.wikipedia.org/wiki/Unix_time), seconds since Jan 01 1970 (UTC), as firmware version.
For non-Pelion firmware OTA, their firmware versions must be string of such format.
In POSIX-like environment, it can acquire by running `date +%s`:

```sh
$ date +%s
1576821050
```

### Avoid potential false success

The UCP module can return false success in the following exception cases. The library tries to cover them:

-   Zero access size
-   Unaligned access (done by buffering above)
-   Access beyond firmware size

## Call sequence for writing downloaded firmware

To utilize this library to write downloaded firmware, user must follow the call sequence:

1.  Prepare for writing a new firmware image with `MBEDBL_UCP_PrepareWrite(...)`

    ```C
    /** Prepare for writing a new firmware image to the specified location
     *
     * @param ucp_ctx           UCP context where to initialize for write below
     * @param location          Storage location where to write the new firmware image. Only 0 ~ (MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS - 1)
     * @param firmware_version  Firmware version. Must be UNIX timestamp in C-string format, like "1574817760".
     *                          Can acquire by running 'date +%s' on POSIX-like environment.
     * @param firmware_size     Firmware size in bytes
     * @return                  0 on success, -1 on failure
     */
    ```

    The firmware version passed in as stated above must be in Unix timestamp format.
    The firmware size passed in must be exact, which is used to calculate out needed storage space and to help validate firmware OTA in committing to write step below.

1.  Write a downloaded firmware fragment with `MBEDBL_UCP_Write(...)`

    ```C
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
    ```

    Usually, a firmware fragment to write is not aligned and will be buffered for aligned write.
    If it is already aligned, it won't be buffered and will be directly written.
    If it is large enough to across several pages, the complete pages in the middle won't be buffered and will be directly written.

1.  Commit to writing with `MBEDBL_UCP_FinalizeWrite(...)`

    ```C
    /** Commit to writing the firmware image
     *
     * @param ucp_ctx   UCP context initialized in MBEDBL_UCP_PrepareWrite
     * @return          0 on success, otherwise -1 on failure
     */
    ```

    Take special care of committing to write.
    Validate downloaded firmware according to firmware OTA protocol first, and then commit to write on success.
    Otherwise, false success may happen and mbed-bootloader cannot detect it out.

## Example

To utilize this library, storage layout of mbed-bootloader and firmware OTA application must be consistent.
On Mbed OS, storage layout involves some non-trivial configurations.
Please see [mbed-bootloader](https://github.com/ARMmbed/mbed-bootloader) and firmware OTA examples below for details.

### Firmware OTA examples

-   [Nuvoton's Alibaba Cloud IoT C-SDK firmware OTA example](https://github.com/OpenNuvoton/NuMaker-mbed-Aliyun-IoT-CSDK-OTA-example)
