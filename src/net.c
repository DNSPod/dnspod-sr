/* Copyright (c) 2006-2012, DNSPod Inc.
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */


#include "net.h"


//reserved ip
//10.0.0.0:8
//172.16.0.0:12
//192.168.0.0:16
//0.0.0.0
//255.255.255.255
//127.0.0.0:8
//224.0.0.0:18
int
check_client_addr(struct sockaddr_in *addr)
{
    return 0;
}


//add fd to backdoor
//only 1 udp fd at first
int
add_backdoor(int fd)
{
    int epfd, ret;
    struct epoll_event ev = {0};
    epfd = epoll_create(BACK_EVENT);
    if (epfd < 0)
        dns_error(0, "epoll bd");
    ev.data.fd = fd;
    ev.events = EPOLLIN;        //with out EPOLLET
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    if (ret < 0)
        dns_error(0, "epoll add udp backdoor");
    return epfd;
}


int
set_recv_timeout(int fd, int sec, int usec)
{
    int ret;
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = usec;
    ret =
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv,
                   sizeof(struct timeval));
    return ret;
}


int
create_socket(int port, int proto, uchar * addr)
{
    int fd = -1, pt = -1;
    struct sockaddr_in srv;
    if (proto == UDP)
        pt = SOCK_DGRAM;
    else if (proto == TCP)
        pt = SOCK_STREAM;
    fd = socket(AF_INET, pt, 0);
    if (fd <= 0)
        return -1;
    srv.sin_family = AF_INET;
    if (addr == NULL)
        srv.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        /* inet_aton(addr, &srv.sin_addr); */
        inet_pton(AF_INET, (const char *)addr, &srv.sin_addr);
    srv.sin_port = htons(port);
    if (bind(fd, (SA *) & srv, sizeof(srv)) < 0) {
        perror("bind:");
        return -1;
    }
    if (proto == SOCK_STREAM)
        listen(fd, 512);
    return fd;
}


int
connect_to(struct sockinfo *si)
{
    int ret = 0;
    //printf("CONN!!!\n");
    socklen_t len = sizeof(struct sockaddr_in);
    ret = connect(si->fd, (SA *) & si->addr, len);
    if (ret < 0) {
        if (errno == EINPROGRESS)
            return 0;
        printf("%d,%d,", si->fd, errno);
        perror("conn");
        return -1;
    }
    return 0;
}


int
tcp_write_info(mbuf_type *mbuf, int vi)     //for dns only
{
    int i, ret;
    ret = send(mbuf->fd, mbuf->buf, mbuf->buflen, MSG_NOSIGNAL);
    if (ret < 0) {
        printf("%d,", errno);
        perror("tcp send");
    }
    if (vi == 1) {
        printf("fd is %d\n", mbuf->fd);
        for (i = 0; i < mbuf->buflen; i++)
            printf("%x,", mbuf->buf[i]);
        printf("\n");
    }
    return ret;
}


int
udp_write_info(mbuf_type *mbuf, int vi)
{
    int i, ret;
    socklen_t len;
    if (vi) {
        dbg_print_addr((struct sockaddr_in *) (mbuf->addr));
        for (i = 0; i < mbuf->buflen; i++)
        {
            if (i % 16 == 0)
                printf("\n");
            printf("%02x,", mbuf->buf[i]);
        }
        printf("\n");
    }
    len = sizeof(struct sockaddr_in);
    ((struct sockaddr_in *) (mbuf->addr))->sin_family = AF_INET;
    ret = sendto(mbuf->fd, mbuf->buf, mbuf->buflen, 0, (SA *) (mbuf->addr), len);
    /* if (ret < 0) { */
        /* perror("write udp"); */
        /* printf("len %u,fd %d\n", len, ri->fd); */
        /* dbg_print_addr((struct sockaddr_in *) &(ri->addr)); */
        /* for (i = 0; i < ri->buflen; i++) */
            /* printf("%x,", ri->buf[i]); */
        /* printf("\n"); */
    /* } */
    return ret;
}


int
tcp_read_dns_msg(mbuf_type *mbuf, uint max, int vi) //for dns only.
{
    int ret = 0, tp, rcvnum;
    uchar buf[4] = { 0 };
    ushort le = 0;
    tp = recv(mbuf->fd, buf, 2, 0);
    if (tp < 0) {
        printf("%d,", mbuf->fd);
        perror("tp");
        return -1;
    }
    if (tp == 0)                //peer closed
        return 0;
    memcpy(&le, buf, sizeof(ushort));
    le = ntohs(le);
    if (le > max) {
        printf("too large %d,%u,%d\n", mbuf->fd, le, max);
        return -1;
    }
    while (ret < le)            //should set time out here
    {
        rcvnum = recv(mbuf->fd, mbuf->buf + ret, mbuf->buflen - ret, 0);
        if (rcvnum < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            printf("tcp data %d,%d,%d", mbuf->fd, le, ret);
            perror("tcp read");
            return -1;
        }
        if (rcvnum == 0) {
            ret = -1;
            break;
        }
        ret += rcvnum;
    }
    return ret;
}


int
udp_read_msg(mbuf_type *mbuf, int visible)
{
    int ret, i;
    socklen_t len = sizeof(struct sockaddr_in);
    ret =
        recvfrom(mbuf->fd, mbuf->buf, mbuf->buflen, 0, (SA *)(mbuf->addr),
                 &len);
    if (ret < 0) {
        //perror("read udp");
        return ret;
    }
    //printf("%d,",ret);
    //dbg_print_addr(&si->addr);
    if (visible) {
        for (i = 0; i < ret; i++)
            printf("%x,", mbuf->buf[i]);
        printf("\n");
    }
    return ret;
}


int
set_sock_buff(int fd, int m)
{
    int ret;
    int bufsize = m * 1024 * 1024;      //1m
    if (fd <= 0)
        return -1;
    ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                     (const uchar *) &bufsize, sizeof(int));
    return ret;
}


int
set_non_block(int fd)
{
    int opt = fcntl(fd, F_GETFL, 0);
    if (opt < 0)
        return -1;
    opt |= O_NONBLOCK;
    return (fcntl(fd, F_SETFL, opt));
}


int
make_bin_from_str(uchar * bin, const char * str)
{
    int i;
    uchar val = 0;
    for (i = 0; i < 4; i++) {
        while ((str[0] != '.') && (str[0] != 0)) {
            val = val * 10 + str[0] - '0';
            str++;
        }
        str++;                  //jump '.'
        bin[0] = val;
        val = 0;
        bin++;                  //next digit
    }
    return 0;
}


int
make_addr_from_bin(struct sockaddr_in *addr, uchar * data)
{
    uchar ipv4[16] = { 0 };
    int idx = 0;
    int i;
    ushort val = 0;
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0)
        return -1;
    for (i = 0; i < 4; i++) {
        val = (ushort) data[i];
        if (val > 99) {
            ipv4[idx] = val / 100 + '0';
            idx++;
        }
        if (val > 9) {
            ipv4[idx] = (val % 100) / 10 + '0';
            idx++;
        }
        ipv4[idx] = val % 10 + '0';
        idx++;
        ipv4[idx] = '.';
        idx++;
    }
    ipv4[idx - 1] = 0;
    i = inet_pton(AF_INET, (const char *)ipv4, &addr->sin_addr);
    return 0;
}


//---------------------debug-------------------------------
int
dbg_print_addr(struct sockaddr_in *addr)
{
    uint i;
    if (addr == NULL) {
        printf("null addr\n");
        return 0;
    }
    i = addr->sin_addr.s_addr;
    printf("%u.%u.%u.%u\n", i % (256), i / 256 % 256, i / 256 / 256 % 256,
           i / 256 / 256 / 256);
    return 0;
}
