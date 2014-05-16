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



//write log
//write data file
//read data file

#ifndef _IO_H
#define _IO_H

#include "dns.h"
#include <sys/stat.h>           //read and write files
#include <sys/types.h>


int read_config(const char *, char *, struct htable *, char **);


#define LOG_INTERVAL (900)

#define TYPE_FETCHER (112)
#define TYPE_QUIZZER (233)


enum {
    NEVER_EXPIRED1 = 172800,
    NEVER_EXPIRED2 = 518400,
};

#define LOG_CACHE_SIZE (1024 * 1024)

struct log_info {
    int logfd;
    time_t lastlog;
    int log_type;
    uchar log_cache[LOG_CACHE_SIZE];
    int log_cache_cursor;
};
//idx and lastlog and logfd
//first argu
int create_new_log(uchar * prefix, int idx, int type);
int write_log(struct log_info *, int, const uchar *, int, int, 
              struct sockaddr_in *);
int read_root(struct htable *, struct rbtree *);
int refresh_records(struct htable *, struct rbtree *);

uchar * jump_space(uchar * itor);
#endif
