# Installation

## Compile

Run make in ./src to produce binary

    make

## Command Line Options

* -c
  Config file

* -h
  Help

* -f
  Forward

* -d
  Daemon

* -v
  Print version
   
## config file

The default configuration file is sr.conf，other wise you can pass in the command line parameter

    ./dnspod-sr -c /path/of/sr.conf    

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

Configure the listen port:
    listen:9054
    
Configure the root file name
    root:root.z

Configure the records file name
    records:records.z

