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


#ifndef _NET_H
#define _NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include "utils.h"
#include "memory.h"

typedef struct sockaddr SA;

#define MAX_TCP_SIZE (2048)
#define MAX_UDP_SIZE (512)

#define TCP (SOCK_STREAM)
#define UDP (SOCK_DGRAM)


#define BACK_EVENT (1000)


//the socket information
//use to identify client and auth server
struct sockinfo {
    struct sockaddr_in addr;
    int fd, buflen, socktype;
    uchar *buf;
    packet_type *lowerdomain;
    mbuf_type *mbuf;
};


int create_socket(int, int, uchar *);

int add_backdoor(int fd);
int udp_write_info(mbuf_type *mbuf, int);
int udp_read_msg(mbuf_type *mbuf, int);
int tcp_write_info(mbuf_type *mbuf, int);
int tcp_read_dns_msg(mbuf_type *mbuf, uint, int);   //len_msg.
int connect_to(struct sockinfo *);

struct fds *create_fds(int fd, int type);
int set_time_out(int fd, int sec, int usec);
int set_recv_timeout(int fd, int sec, int usec);
int set_non_block(int fd);
int set_sock_buff(int fd, int m);

int check_client_addr(struct sockaddr_in *);
int dbg_print_addr(struct sockaddr_in *);


int make_bin_from_str(uchar * bin, const char * str);
int make_addr_from_bin(struct sockaddr_in *addr, uchar * data);

#endif
