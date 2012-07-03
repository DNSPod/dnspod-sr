# 如何安装

## 编译
./src目录下执行 make 即可编译出可执行文件

    make

## 配置文件
默认配置文件为当前目录下的 sr.conf，也可以在命令行参数中指定

    ./dnspod-sr /path/of/sr.conf

当前配置文件中支持为特定域名指定外部递归 DNS，以 xfer 开头，如下:

    xfer:
    googleusercontent.com.:8.8.8.8
    google.com.:8.8.8.8
    youtube.com.:8.8.8.8
    s-static.ak.facebook.com.edgekey.net.:8.8.8.8
    :

最后一行以`:`结束。

配置日志文件目录（可选）

    log_path:
    ./log/
