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


#ifndef _AUTHOR_H
#define _AUTHOR_H


#include "io.h"


enum
{
 FETCHER_NUM = 2,
 SERVER_PORT = 53,
};


enum
{
 QUIZZER_NUM = 2,
};


enum
{
 NEW_QUERY = 0,
 PROCESS_QUERY = 1,
 TTL_UPDATE = 3,
};


#define SRV_ADDR ("127.0.0.1")

enum
{
 //MAX_TRY_TIMES = 15,
 REFRESH_INTERVAL = 10,
 AUTH_DB_NUM = 101,
 BIG_MEM_STEP = 2000,
 RANDOM_SIZE = 3000,
 ID_SPACE = 60000,
 AUTH_DATA_LEN = 65528, //for meta data
 EP_TCP_FDS = 65530,
};


enum
{
 LIST_SPACE = 10000,
};


struct author
{
 int audp, //read and send auth server, private
 cudp, //send to client, share with other author
 idx;
 struct server *s;
 pthread_mutex_t lock;//protect list above
 struct qoutinfo *list[LIST_SPACE];
 //statis
 int qnum;
 int response;
 int qidx;
 int timex;
 ////
 struct list *el;
 time_t lastlog;
 int bdepfd,logfd;
 pthread_mutex_t dblock[AUTH_DB_NUM]; //protect db in disk
 uchar databuffer[AUTH_DATA_LEN];
 uchar randombuffer[RANDOM_SIZE];
 int rndidx;//no lock
 int dataidx;//no lock
 uchar ip[IP_DATA_LEN];//shared by all qoutinfos
 int eptcpfds[EP_TCP_FDS];
 uint rdb;//records in db
 int ddbefore;
 int underattack;
 int tcpinuse;
 struct htable *fwd;
 struct htable *ds;
 int dupbefore; //only used in main thread
 int limits;   //only used in main thread
 int hsidx;
 //statistics
 uint quizz;
 uint drop;
 uint timeout;
};


struct fetcher
{
 int idx;
 struct server *s;
 struct msgcache *mc;
 struct list *el;
 int logfd;
 time_t lastlog;
 uchar databuffer[65536];
 int dataidx;
 int qidx;
 //statistics
 uint pkg;
 uint send;
 uint miss;
};


struct server
{
 ushort nquizzer,nfetcher;
 int ludp,ltcp; //out udp
 struct fetcher *fetchers;
 struct author *authors;
 struct list eventlist;
 struct htable *datasets;
 struct htable *forward;
 //struct htable *rootz;
 struct htable *qlist; //same domain same type only query once.
 ulong pkg;
 uchar logpath[255];
 ulong recordsindb;
 struct rbtree *ttlexp;
 //pthread_mutex_t lock;//protect ttlexp
 uint16_t refreshflag;
 time_t lastrefresh;
};


struct seninfo
{
 uint len;
 uint type;
 union
 {
  int fd;
  struct sockaddr_in addr;
 };
};


void* run_quizzer(void*);
int run_fetcher(struct fetcher *f);
int write_back_to_client(uchar*,uchar*,ushort,int,struct sockinfo*,uchar*,int);
int global_cron(struct server*);
int find_from_db(struct baseinfo *qi,struct fetcher *f);

#endif
