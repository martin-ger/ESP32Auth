# BLE FIDO Authenticator

(Up to now only BLE interface, no functionality)

Integrates the solokey/solo project for handling the CTAP stuff.

Creates GATT server and then starts advertising, waiting to be connected to a GATT client.

It uses ESP32's Bluetooth controller and NimBLE stack based BLE host.

SMP parameters like I/O capabilities of device, Bonding flag, MITM protection flag and Secure Connection only mode etc., can be configured through menuconfig options.

To test this, any BLE scanner app can be used.

### Configure the project

```
idf.py menuconfig
```

* Set serial port under Serial Flasher Options.

* Select I/O capabilities of device from 'Example Configuration > I/O Capability', default is 'Just_works'.

* Enable/Disable other security related parameters 'Bonding, MITM option, secure connection(SM SC)' from 'Example Configuration'.

### Build and Flash

Clone this repository using:

```
git clone --recurse-submodules https://github.com/martin-ger/ESP32Auth.git
```

Build the project and flash it to the board, then run monitor tool to view serial output:

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for full steps to configure and use ESP-IDF to build projects.

## Note
* NVS support is not yet integrated to bonding. So, for now, bonding is not persistent across reboot.
