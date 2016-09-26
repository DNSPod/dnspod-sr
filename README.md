# DNSPod Security Recursive DNS Server

dnspod-sr is a run on the Linux platform, high-performance recursive DNS server software, high performance, high-load, easy to expand the advantages of non-BIND and other software can match.

## characteristic

   1.  High-performance, than all the popular open source DNS software performance higher than 2 times
   2. Security, generally can withstand attacks
   3. Stability, reduce the resolution failure rate
   4. Initiative to refresh the cache, and faster response
   5. Easy to extend, very easy to deploy
   6. Pollution, contamination can correctly parse the domain name

## performance

dnspod-sr relying on DNSPod years experience operating, and optimizing DNS services, complex network for the domestic situation, a series of recursive DNS optimization, compared with other open source software, performance is greatly improved.

#### test environment

Gigabit Ethernet, 4-core CPU, 4G memory, Linux 64-bit systems.

#### Performance Testing

    dnspod-sr: 15 Wan qps
    BIND 9.9: 7 Wan qps
    unbound 4.7: 8 Wan qps
    
![Benchmark](https://github.com/DNSPod/dnspod-sr/raw/master/benchmark.png)

Benchmark
solution

    Setup dnspod-sr cluster, replace implementation based on the current BIND obsolete programs to reduce operating costs
    Companies, schools, government and other organizations internal DNS, resolving external invisible private domain, to improve Internet speed

## Quick Start

Download Source:

    git clone https://github.com/DNSPod/dnspod-sr.git
    cd dnspod-sr

## Or download the archive:

    https://github.com/DNSPod/dnspod-sr/zipball/master

# Compile the code:

    cd src
    make

run

    ./dnspod-sr

## Roadmap

    Support for cluster deployment

## Documentation & Feedback

   - Wiki: https://github.com/DNSPod/dnspod-sr/wiki
   - FAQ: https://github.com/DNSPod/dnspod-sr/wiki/FAQ
   - Issues: https://github.com/DNSPod/dnspod-sr/issues
   - Submit feedback https://github.com/DNSPod/dnspod-sr/issues/new

## Open source license

dnspod-sr is licensed under the BSD License.
