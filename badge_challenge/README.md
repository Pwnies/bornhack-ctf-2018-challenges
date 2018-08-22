# Badge Challenge

This challenge is based on the code from https://os.mbed.com/teams/Bluetooth-Low-Energy/code/BLE_GATT_Example/.

To build:
```
pip install --user mbed-cli
mbed deploy
mbed compile
```
If something goes wrong, try running `mbed update` and hope for the best.

To get it on the badge:
 * Get the badge repo https://github.com/bornhack/badge2018/ and checkout the branch `nrf51prog`
 * Set the badge in BOOT mode, and compile/download the firmware with `sudo make dfu`
 * Check that both GeckoBoot and nRF51 appear when you run `sudo dfu-util --list`
 * Download the newly built firmware with something like `sudo dfu-util -d 0483:5740 -a nRF51 -i1 -D path_to_BLE_GATT_hex_file`
 * Power cycle the badge for the firmware to take effect
