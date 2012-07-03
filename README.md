# DNSPod Security Recursive DNS Server


## 关于
dnspod-sr 是一个运行在 Linux 平台上的高性能的递归 DNS 服务器软件，具备高性能、高负载、易扩展的优势，非 BIND 等软件可以比拟。

## 特性
1. 高性能，比所有流行的开源 DNS 软件性能高出2倍以上
2. 安全，能抵御一般攻击
3. 稳定，有效降低解析失败率
4. 主动刷新缓存，响应速度更快
5. 易于扩展，非常容易部署
6. 防污染，能够正确解析被污染域名


## 性能
dnspod-sr 依托于 DNSPod 多年运营和优化 DNS 服务的经验，针对国内复杂的网络情况，对递归 DNS 进行了一系列的优化，比较其他开源软件，性能得到大幅提升。

#### 测试环境
千兆网卡，4核 CPU，4G 内存，Linux 64位系统。

#### 性能测试
- dnspod-sr: 15万 qps
- BIND 9.9: 7万 qps
- unbound 4.7: 8万 qps

![Benchmark](https://github.com/DNSPod/dnspod-sr/raw/master/benchmark.png)

## 解决方案
1. 架设 dnspod-sr 集群，替换各大运营商目前基于 BIND 的陈旧方案，减少运营成本
2. 公司、学校、政府等组织内部 DNS，解析外部不可见的私有域名，提高上网速度

## 快速开始
下载源码：

    git clone https://github.com/DNSPod/dnspod-sr.git
    cd dnspod-sr

或者下载压缩包：

    https://github.com/DNSPod/dnspod-sr/zipball/master

编译源码：

    cd src
    make

运行

    ./dnspod-sr


## Roadmap
- 支持集群式部署

## 文档 & 反馈
- Wiki: <https://github.com/DNSPod/dnspod-sr/wiki>
- FAQ: <https://github.com/DNSPod/dnspod-sr/wiki/FAQ>
- Issues: <https://github.com/DNSPod/dnspod-sr/issues>
- [提交反馈](https://github.com/DNSPod/dnspod-sr/issues/new)

## 开源协议
dnspod-sr 在 BSD License 下发布。
