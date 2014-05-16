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


#ifndef _EVENT_H
#define _EVENT_H

#include "author.h"
#include "memory.h"

#define SENTINEL_EVENT (1000)

struct event_data;
struct worker;
struct baseinfo;
struct sockinfo;
typedef int (*noti_chain_callback) (struct event_data *, void *, int);


struct event_data {
    int fd;
    noti_chain_callback cb;
    void *ext;
};


struct iner_event;
struct event {
    int size;
    int onexit;
    struct iner_event *ie;
    struct event_data data[0];
};


enum event_type {
    ET_READ = 1,
    ET_WRITE = 2,
    ET_ALL = 3,
};


struct event_help {
    int fd;
    int spfd;
    int num;
    enum event_type type;
    struct timeval *to;
    noti_chain_callback cb;
    void *ext;
};


int run_sentinel(struct server *s);
int run_fetcher(struct fetcher *w);


struct event *create_event(int);
int add_event(struct event *, struct event_help *);
int del_event(struct event *, struct event_help *);
int deinit_event(struct event *, struct event_help *);
int wait_event(struct event *, struct event_help *);

#endif
