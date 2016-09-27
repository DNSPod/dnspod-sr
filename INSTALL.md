# Installation

## Compile

Run make in ./src to produce binary

    make

## config file

The default configuration file is sr.conf，other wise you can pass in the command line parameter

    ./dnspod-sr /path/of/sr.conf

In the current configuration file, you can specify external recursive DNS for a specific domain name starting with xfer as follows:

    xfer:
    googleusercontent.com.:8.8.8.8
    google.com.:8.8.8.8
    youtube.com.:8.8.8.8
    s-static.ak.facebook.com.edgekey.net.:8.8.8.8
    :

The last line ends with a `:`.

Configure the log directory(optional)

    log_path:
    ./log/
