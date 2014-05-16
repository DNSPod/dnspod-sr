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



#ifndef _STORAGE_H
#define _STORAGE_H

#include "utils.h"
#include "datas.h"
#include "memory.h"
#include <ctype.h>
#include <assert.h>

//rfc 2817
#define MAX_TTL (7 * 86400)
//no rfc
#define MIN_TTL (10)


////////////////////////memory chunk/////////////////////////
struct msgcache {
    uint64_t head, tail;
    uint32_t size, pkt;
    pthread_spinlock_t lock;       //protect head and tail
    uchar data[0];
};


struct msgcache *init_msgcache(int n);
void free_msgcache(struct msgcache *);
/////////////////////////////////////////////////////////////


enum {
    MAX_MSG_SEG = 32,
    MAX_MSG_SIZE = 2048,
};


//used by memory hash and disk db
struct mvalue {
    uint16_t len;
    uint16_t num;
    uint32_t ttl;
    uint32_t hits;
    uint16_t seg;               //when there is no memory segment, seg == 0
    //uint16_t off.
    //something...
};


///////////////////////memory hash///////////////////////////
typedef hashval_t(hashfunc) (void *data, int);
typedef int (comparefunc) (void *, void *);
typedef int (delkeyfunc) (void *);
typedef int (delvalfunc) (void *);


//we can hold at least HASH_TABLE_SIZE * MULTI_HASH elements
//slot size
#define HASH_TABLE_SIZE  (65536)
#define MULTI_HASH (10)
extern const uint MAX_ELE_NUM;
//MAX_RECORD_SIZE bytes at most
#define MAX_RECORD_SIZE (1000)

#define QLIST_MAX_ELE_NUM (200000)
#define QLIST_TABLE_SIZE (4095)
#define GET_AID(i, typeoff)     (i | (typeoff << 12))
#define GET_IDX(i)     (i & 0x0FFF)
#define GET_TYPE(i)     (i >> 12)

//types we support at the moment
extern const enum rrtype support_type[];
// #define SUPPORT_TYPE_NUM    (9)
// typedef struct _type_value
// {
//     uchar   *A;
//     uchar   *NS;
//     uchar   *CNAME;
//     uchar   *SOA;
//     uchar   *MX;
//     uchar   *TXT;
//     uchar   *AAAA;
//     uchar   *SRV;
//     uchar   *PTR;
// }type_value;

struct hentry {
    union {
        uchar *vals[SUPPORT_TYPE_NUM];
        type_value val;
    };
    struct hentry *next;
    int count;
    uchar key[0];
};


struct hdata {
    struct hentry *list;
    uint64_t now;
    pthread_spinlock_t lock;
};


struct htable {
    pthread_spinlock_t lock;       //protect now
    struct hdata *table;
    uchar *edata;
    hashfunc *h;
    uint size, mask, now;
    comparefunc *c;
};

struct htable *htable_create(hashfunc * h, comparefunc * c, int, int);
int htable_insert(struct htable *, uchar *, int, int, uchar *, int, struct mvalue *, hashval_t *hashd);
uchar *htable_delete(struct htable *ht, uchar * key, int klen, int type, hashval_t hashd);
int htable_find(struct htable *ht, uchar * key, int klen, int type, uchar * buffer, int vlen,
                struct mvalue *metadata, hashval_t *hashd);
int htable_find_io(struct htable *ht, int idx,/* int off, uchar * buffer, 
                   uchar * key, int *klen, int vlen,*/ uint32_t limit,
                   struct rbtree *rbt, int ttl_update);
uint get_pre_mem_hash(void *, int klen, hashval_t *hashd);
int find_record_with_ttl(struct htable *, uchar *, int, int, uchar *, int,
                         struct mvalue *metadata, hashval_t *hash);

int htable_find_list_io(struct htable *ht, int idx, int off, int *typeoff, uchar **buffer);
int htable_find_list(struct htable *ht, uchar *key, int typeoff, int idx, uchar **buffer);
uchar *htable_delete_list_io(struct htable *ht, int typeoff, int idx, int off);
uchar *htable_delete_list(struct htable *ht, uchar *key, int typeoff, int idx);
int htable_insert_list(struct htable *, uchar *, int, int, uchar *, int, struct mvalue *, hashval_t *hashd);

#endif
