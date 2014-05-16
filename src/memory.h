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



#ifndef _MEMORY_H
#define _MEMORY_H

// #include "author.h"
// #include "net.h"
// #include "dns.h"
// #include "storage.h"
#include "utils.h"

#include <netinet/in.h>
#include <assert.h>

#define MEMPOOL_SIZE    (262144)

#define RING_SP_ENQ 0x0001
#define RING_SC_DEQ 0x0002

struct mbuf_ring {
    /** Ring producer status. */
    struct prod {
        uint32_t watermark;
        uint32_t sp_enqueue;
        uint32_t size;
        uint32_t mask;
        volatile uint32_t head;
        volatile uint32_t tail;
    } prod __attribute__((__aligned__(64)));

    /** Ring consumer status. */
    struct cons {
        uint32_t sc_dequeue;
        uint32_t size;
        uint32_t mask;
        volatile uint32_t head;
        volatile uint32_t tail;
    } cons __attribute__((__aligned__(64)));
    void *ring[0] __attribute__((__aligned__(64))); 
};

#define MBUF_DATA_LEN   (2048)
typedef struct _mem_buf {
    struct mbuf_ring *mbuf;
    uint fetch_len;
    uint socktype;
    int fd;
    struct sockaddr_in *addr, caddr, aaddr;
    uchar data[MBUF_DATA_LEN];

    enum rrtype qtype;
    int err;
    int dlen;
    ushort id;
    packet_type lowerdomain;
    uchar *origindomain;
    
    int buflen;
    uchar *buf;

    uchar *td;                  //type and domain
    ushort cid, qlen;           //include 0
    ushort lables;
    //query info
    uchar *qing;
    hashval_t *qhash;
    ushort backid;
    ushort aid, mask;           //auth id,domain mask
    ushort qname;               //type
    //status info
    ushort sq;                  //send query flag
    ushort qtimes;              //ns,cname,domain
    ushort auth_socktype, stat;      //this may be diffefrent from client's socktype
    uchar qbuffer[256];
    hashval_t qbuffer_hash;
    uchar *tdbuffer;
    uchar *tempbuffer;
    uchar *dmbuffer;
    uchar *ipbuffer;
    ushort hascname;
    int tcpfd;
    int tcpnums;
    int mxtry;
    int qns;
    uint64_t stime;
    
//     union {
//         uchar *vals[SUPPORT_TYPE_NUM];
//         type_value val;
//     };
//     struct hentry *next;
//     int count;
//     uchar key[256];
    
//     union {
//         struct baseinfo bi;
//         struct sockinfo si;
//         struct qoutinfo qi;
//         struct hentry he;
//     } info;
    
} mbuf_type;

int mempool_create(uint32_t num);
mbuf_type *mbuf_alloc();
int mbuf_free(mbuf_type *mbuf);

#endif