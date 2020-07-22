# esp-idf-libssh

This repository contains a port of [libssh](https://www.libssh.org/) to the [Espressif IoT Development Framework](https://github.com/espressif/esp-idf/).
The libssh code itself lives unmodified in a git submodule, but it is augmented with additional esp-idf header files and component glue.
Additionally, an embeddable ssh server (sshd) is included as an example esp-idf project.

# Running the sample project

You need to edit the example project's `main.c` and add your WiFi SSID and password.
You should also want to edit `sshd_task.c` and replace the default username and host key.
Assuming esp-idf is installed, build and flash the project as usual:

```sh
$ cd examples/sshd
$ idf.py menuconfig
$ idf.py build
$ ipf.py -p /dev/ttyU0 flash
$ idf.py -p /dev/ttyU0 monitor
...
I (2000) wifi:connected with ..., aid = 1, channel 1, BW20, bssid = ...
I (2000) wifi:security: WPA2-PSK, phy: bgn, rssi: -46
I (2000) wifi:pm start, type: 1

I (2100) wifi:AP's beacon interval = 102400 us, DTIM period = 1
I (3710) tcpip_adapter: sta ip: 10.0.105.139, mask: 255.255.255.0, gw: 10.0.105.
```

Note the IP address in the log and open a ssh session to it. If you didn't change the credentials, the default account name is `neo` with password `trinity`.

```sh
$ ssh neo@10.0.105.139
neo@10.0.105.139's password: trinity

 _  _     _ _        __      __       _    _
| || |___| | |___    \ \    / /__ _ _| |__| |
| __ / -_) | / _ \_   \ \/\/ / _ \ '_| / _` |
|_||_\___|_|_\___( )   \_/\_/\___/_| |_\__,_|
                 |/
Welcome to minicli! Type ^D to exit and 'help' for help.
minicli> help
        banner
        help

minicli> ^DConnection to 10.0.105.139 closed.
```

The included "minicli.c" is a very simple command line interface that I copied from an old 8-bit microcontroller project of mine.
But it is easy to extend with more commands and shows how to interface sessions with the ssh server.
