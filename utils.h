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
#include <stdint.h> //for uint32_t

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


extern time_t global_now; //defined in init.c


enum utils_numberic
{
 DEBUG_TIMES = 500,
};


struct list_node
{
 void *data;
 struct list_node *next;
};


//list header
struct list
{
 pthread_mutex_t lock;
 struct list_node *head;
};


struct ttlnode
{
 uint exp; //expired time
 ushort dlen; //data len
 uchar *data; //
};


int trig_signals(int);
void drop_privilege(uchar*);

uchar* get_str(uchar *str,int len);
void put_str(uchar*);

int dict_comp_uint_equ(void *a,void *b);
int dict_comp_str_equ(void *a,void *b);
int rbt_comp_uint_gt(void *v1,void *v2,void *argv);
int rbt_comp_ttl_gt(void *v1,void *v2,void *argv);

void dns_error(int,char*);
int dbg(const char *format, ...);
void print_hex(uchar *val,int n);

int str_to_uchar4(const char *addr,uchar *val);
int str_to_uchar6(uchar *addr,uchar *val);
int to_uppercase(uchar *buf,int n);
int to_lowercase(uchar *buf,int n);
int fix_tail(char *domain);

int empty_function(int);
void insert_mem_bar(void);
int test_lock(pthread_mutex_t *lock);

int set_bit(ushort*,int);
int clr_bit(ushort*,int);
int tst_bit(const ushort,int);


int get_random_data(uchar*,int);

int get_time_usage(struct timeval *tv,int isbegin);
int is_uppercase(int c);
int is_lowercase(int c);

hashval_t uint_hash_function(void *ptr);
hashval_t nocase_char_hash_function(void *argv);

int slog(uchar *msg,int fd,pthread_mutex_t *lock);

#endif
