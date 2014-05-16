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


#ifndef _UTILS_H
#define _UTILS_H

//standard c headers
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>             //for uint32_t

//unix system headers
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef uint32_t hashval_t;


extern time_t global_now;       //defined in init.c


enum utils_numberic {
    DEBUG_TIMES = 500,
};

typedef struct _packet_type{
    uint8_t label_count ;
    uchar   domain[256];
    uint8_t *label[64];
    uint8_t label_offsets[64];
    uint8_t label_len[64];
    hashval_t hash[64];
//     uchar   origindomain[256];
} packet_type;


struct list_node {
    void *data;
    struct list_node *next;
};


//list header
struct list {
    pthread_spinlock_t lock;
    struct list_node *head;
};


struct ttlnode {
    uint exp;                   //expired time
    ushort dlen;                //data len
    ushort type;
    hashval_t *hash;
    packet_type *lowerdomain;
    uchar *data;                //
};

enum rrtype {
    BEGIN_TYPE = 0, A = 1, NS = 2,
    MD = 3, MF = 4, CNAME = 5, SOA = 6,
    MB = 7, MG = 8, MR = 9, NUL = 10,
    WKS = 11, PTR = 12, HINFO = 13,
    MINFO = 14, MX = 15, TXT = 16, RP = 17,     //rfc1183
    AFSDB = 18,                 //rfc1183
                                        /*gap */ SIG = 24, KEY = 25,
                                        //rfc2065
    /*gap */ AAAA = 28, /*gap */ NXT = 30,      //rfc2065
                                /*gap */ SRV = 33,
                                //rfc2782
    CERT = 37,                  //rfc4398
    /*gap */ A6 = 38, DNAME = 39, /*rfc2672 *//*gap */ OPT = 41,        //for edns0
    APL = 42, /*rfc3123 */ DS = 43,     //rfc3658
                                /*gap */ RRSIG = 46,
                                //rfc4034
    NSEC = 47, DNSKEY = 48, DHCID = 49, /*rfc4701 *//*gap */ TKEY = 249,
    /*gap */ AXFR = 252, MAILB = 253,
    MAILA = 254,                //obsolete
    ANY = 255,             //*,a request for all records
};

#define SUPPORT_TYPE_NUM    (9)
typedef struct _type_value
{
    uchar   *A;
    uchar   *NS;
    uchar   *CNAME;
    uchar   *SOA;
    uchar   *MX;
    uchar   *TXT;
    uchar   *AAAA;
    uchar   *SRV;
    uchar   *PTR;
}type_value;

typedef int (comprbt) (void *, void *, void *);

#define RED (1)
#define BLACK (0)

struct rbnode {
    struct rbnode *parent;
    struct rbnode *left;
    struct rbnode *right;
    int color;
    void *key;
};

struct rbtree {
    struct rbnode *root, nil;
    pthread_spinlock_t lock;
    uint size;
    comprbt *c;
    void *argv;
};

int trig_signals(int);
void drop_privilege(char *);

uchar *get_str(uchar * str, int len);
void put_str(uchar *);

int dict_comp_uint_equ(void *a, void *b);
int dict_comp_str_equ(void *a, void *b);
int rbt_comp_uint_gt(void *v1, void *v2, void *argv);
int rbt_comp_ttl_gt(void *v1, void *v2, void *argv);

void dns_error(int, char *);
int dbg(const char *format, ...);
void print_hex(uchar * val, int n);

int str_to_uchar4(const char *addr, uchar * val);
int str_to_uchar6(uchar * addr, uchar * val);
int to_uppercase(uchar * buf, int n);
int to_lowercase(uchar * buf, int n);
int fix_tail(char *domain);

int empty_function(int);
void insert_mem_bar(void);
int test_lock(pthread_spinlock_t * lock);

int set_bit(ushort *, int);
int clr_bit(ushort *, int);
int tst_bit(const ushort, int);


int get_random_data(uchar *, int);

int get_time_usage(struct timeval *tv, int isbegin);
int is_uppercase(int c);
int is_lowercase(int c);

hashval_t uint_hash_function(void *ptr);
hashval_t nocase_char_hash_function(void *argv, int klen);

int slog(uchar * msg, int fd, pthread_spinlock_t * lock);

extern unsigned char LowerTable[256];
extern unsigned char UpperTable[256];
#define TOLOWER(_ch)  LowerTable[((unsigned char)_ch)]
#define TOUPPER(_ch)  UpperTable[((unsigned char)_ch)]

#define DNS_GET16(num) ((((uint16_t)(num))>>8) | ((uint16_t)((num)<<8)))
#define DNS_GET32(num) ((num >> 24)|((num >>8)&0x0000ff00)|((num << 8)&0x00ff0000)|(num << 24));

#endif
