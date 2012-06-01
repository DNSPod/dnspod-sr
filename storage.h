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
#include <ctype.h>


//rfc 2817
#define MAX_TTL (7 * 86400)
//no rfc
#define MIN_TTL (10)


////////////////////////memory chunk/////////////////////////
struct msgcache
{
 int head,tail;
 uint size;
 pthread_mutex_t lock; //protect head and tail
 uchar data[0];
};


struct msgcache* init_msgcache(int n);
void free_msgcache(struct msgcache*);
/////////////////////////////////////////////////////////////


enum
{
 MAX_MSG_SEG = 15,
 MAX_MSG_SIZE = 1500,
};


//used by memory hash and disk db
struct mvalue
{
 uint16_t len;
 uint16_t num;
 uint32_t ttl;
 uint32_t hits;
 uint16_t seg; //when there is no memory segment, seg == 0
 //uint16_t off.
 //something...
};


///////////////////////memory hash///////////////////////////
typedef hashval_t (hashfunc) (void *data);
typedef int (comparefunc) (void*,void*);
typedef int (delkeyfunc) (void*);
typedef int (delvalfunc) (void*);


//we can hold at least HASH_TABLE_SIZE * MULTI_HASH elements
//slot size
#define HASH_TABLE_SIZE  (65536)
#define MULTI_HASH (10)
extern const uint MAX_ELE_NUM;
//MAX_RECORD_SIZE bytes at most
#define MAX_RECORD_SIZE (1000)


struct hentry
{
 uchar *val;
 struct hentry *next;
 uchar key[0];
};


struct hdata
{
 struct hentry *list;
 pthread_mutex_t lock;
};


struct htable
{
 pthread_mutex_t lock;//protect now
 struct hdata *table;
 uchar *edata;
 uint size,mask,now;
 hashfunc *h;
 comparefunc *c;
};


struct htable* htable_create(hashfunc *h,comparefunc *c,int,int);
int htable_insert(struct htable*,uchar*,uchar*,int,struct mvalue*);
struct hentry* htable_delete(struct htable *ht,uchar *key);
int htable_find(struct htable *ht,uchar *key,uchar *buffer,int vlen,struct mvalue *metadata);
uint get_pre_mem_hash(void*);
int find_record_with_ttl(struct htable*,uchar*,uchar*,int,struct mvalue *metadata);

#endif
