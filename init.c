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



#include "event.h"
#include <sys/time.h>

//----------------------------------------------
time_t global_now = 0;
pthread_mutex_t gnlock;
volatile sig_atomic_t refresh_record = 0;
//----------------------------------------------


extern int daemon(int,int);
struct entry;


static int daemonrize(int dm)
{
 if(dm == 1)
	if(daemon(1,0) == -1)
		dns_error(0,"daemonrize");
	else
		printf("daemon!!!\n"); //we will never see this
 return 0;
}


static int create_listen_ports(int port,int proto,uchar *addr)
{
 int fd = -1;
 fd = create_socket(port,proto,addr);
 if(fd < 0 || set_non_block(fd) < 0)
	{
	 printf("port:%d,proto:%d\n",port,proto);
	 dns_error(0,"fd < 0");
	}
 return fd;
}


int create_author(struct server *s,int n)
{
 int i,j,range;
 pthread_t pt;
 struct author *authors = NULL;
 if(n < 1 || n > 50)
	dns_error(0,"quizzer bad range");
 if((authors = malloc(sizeof(struct author) * n)) == NULL)
	dns_error(0,"out of memory in quizzer");
 s->authors = authors;
 for(i = 0;i < n;i ++)
	{
	 authors[i].idx = i;
	 authors[i].cudp = s->ludp;
	 authors[i].audp = create_listen_ports(i * 1000 + 999,UDP,NULL);
	 if(authors[i].audp < 0)
		dns_error(0,"auth fd error");
	 set_sock_buff(authors[i].audp,1);
	 authors[i].el = &s->eventlist;
	 authors[i].s = s;
	 get_random_data(authors[i].randombuffer,RANDOM_SIZE);
	 authors[i].rndidx = 0;
	 authors[i].dupbefore = 0;
	 authors[i].limits = 10;
	 authors[i].bdepfd = 0;
	 authors[i].fwd = s->forward;
	 authors[i].ds = s->datasets;
	 authors[i].qnum = 0;
	 authors[i].underattack = 0;
	 authors[i].timex = 0;
	 authors[i].response = 0;
	 authors[i].tcpinuse = 0;
	 authors[i].rdb = 0;
	 authors[i].quizz = 0;
	 authors[i].drop = 0;
	 authors[i].timeout = 0;
	 authors[i].qidx = 0;//start idx in qoutinfo list
	 memset(authors[i].ip,0,200);
	 authors[i].lastlog = global_now;
	 authors[i].logfd = create_new_log(s->logpath,i,TYPE_QUIZZER);
	 for(j = 0;j < AUTH_DB_NUM;j ++)
		pthread_mutex_init(&(authors[i].dblock[j]),NULL);
	 for(j = 0;j < LIST_SPACE;j ++)
		authors[i].list[j] = NULL;
	 for(j = 0;j < EP_TCP_FDS;j ++)
		authors[i].eptcpfds[j] = -1;
	 pthread_mutex_init(&authors[i].lock,NULL);
	 authors[i].lastlog = global_now;
	 if(authors[i].cudp < 0 || authors[i].audp < 0)
		dns_error(0,"create quizzer2");
	 if(pthread_create(&pt,NULL,run_quizzer,(void*)&(authors[i])) != 0)
		 dns_error(0,"create quizzer");
	}
 return 0;
}


static int create_fetcher(struct server *s,int n)
{
 int i;
 struct fetcher *ws,*tmp;
 pthread_t pt;
 if(n < 1)
	return -1;
 ws = malloc(sizeof(struct fetcher) * n); //associated a worker with main thread
 if(ws == NULL)
	return -1;
 s->fetchers = ws;
 for(i = 0;i < n;i ++)
	{
	 tmp = ws + i;
	 tmp->s = s;
	 tmp->idx = i;
	 tmp->pkg = 0;
	 tmp->send = 0;
	 tmp->miss = 0;
	 tmp->el = &s->eventlist;
	 tmp->qidx = i % QUIZZER_NUM;
	 tmp->mc = init_msgcache(100);
	 if(tmp->mc == NULL)
		dns_error(0,"get msgcache");
	 tmp->lastlog = global_now;
	 tmp->logfd = create_new_log(s->logpath,i,TYPE_FETCHER);
	 if(tmp->logfd < 0)
		dns_error(0,"log file error");
	 if(pthread_create(&pt,NULL,(void*)run_fetcher,tmp) != 0)
		dns_error(0,"init worker");
	}
 return 0;
}


static struct server* server_init(void)
{
 int i = 0;
 struct server* s = malloc(sizeof(struct server));
 if(s == NULL)
	dns_error(0,"out of memory in server_init");
 s->nfetcher = FETCHER_NUM;
 s->nquizzer = QUIZZER_NUM;
 s->authors = NULL;
 s->fetchers = NULL;
 s->pkg = 0;
 pthread_mutex_init(&s->eventlist.lock,NULL);
 //pthread_mutex_init(&s->lock,NULL);
 s->eventlist.head = NULL;
 if((s->ludp = create_listen_ports(SERVER_PORT,UDP,SRV_ADDR)) < 0)
	dns_error(0,"can not open udp");
 set_sock_buff(s->ludp,10);
 if((s->ltcp = create_listen_ports(SERVER_PORT,TCP,SRV_ADDR)) < 0)
	dns_error(0,"can not open tcp");
 s->datasets = htable_create(NULL,dict_comp_str_equ,HASH_TABLE_SIZE,MULTI_HASH);
 if(s->datasets == NULL)
	dns_error(0,"htable create");
 s->forward = htable_create(NULL,dict_comp_str_equ,1024,1);
 if(s->forward == NULL)
	dns_error(0,"create forward");
 s->qlist = htable_create(NULL,dict_comp_str_equ,LIST_SPACE / 2 * QUIZZER_NUM,1);
 if(s->qlist == NULL)
	dns_error(0,"create qlist");
 s->ttlexp = create_rbtree(rbt_comp_ttl_gt,NULL);
 if(s->ttlexp == NULL)
	dns_error(0,"create ttl tree");
 s->recordsindb = 0;
 s->refreshflag = 0;
 s->lastrefresh = global_now;
 return s;
}


void* time_cron(void *arg)
{
 struct server *s = (struct server*)arg;
 struct timespec tv = {0};
 sigset_t waitset;
 siginfo_t info;
 int ret;
 sigemptyset(&waitset);
 sigaddset(&waitset,SIGUSR1);
 pthread_mutex_init(&gnlock,NULL);
 global_now = time(NULL);
 while(1)
	{
	 tv.tv_sec = 1;
	 tv.tv_nsec = 0;
	 ret = sigtimedwait(&waitset,&info,&tv);
	 if(ret > 0)
		 s->refreshflag = 1;
	 pthread_mutex_lock(&gnlock);
	 global_now ++;
	 pthread_mutex_unlock(&gnlock);
	 //printf("time %lu\n",global_now);
	 if((global_now % 100) == 0)
		{
		 pthread_mutex_lock(&gnlock);
		 global_now = time(NULL);
		 pthread_mutex_unlock(&gnlock);
		}
	}
 return NULL;
}


int sanity_test(int exi)
{
 //rbtree_test();
 if(exi)
	exit(0);
 return 0;
}


int print_basic_debug(void)
{
 printf("[DBG:] max_ele_size is %u - 1808\n",MAX_ELE_NUM);
 printf("[DBG:] server may contain %u useful records\n",(MAX_ELE_NUM - 1808) / 3);
 printf("[DBG:] hash_table_size is %u\n",HASH_TABLE_SIZE);
 printf("[DBG:] we have %u hash tables\n",MULTI_HASH);
 printf("[DBG:] we have %u fetchers,%u quizzers\n",FETCHER_NUM,QUIZZER_NUM);
 return 0;
}


int main(int argc,char **argv)
{
 struct server *s = NULL;
 pthread_t pt;
 if(argc > 2)
	{
	 printf("Too many arguments, please check it\n");
	 exit(-1);
	}
 sanity_test(0);
 drop_privilege("./");
 daemonrize(0);
 trig_signals(1);
 global_now = time(NULL); //for read root.z
 s = server_init();
 read_config(s->logpath,s->forward);
 if(create_fetcher(s,s->nfetcher) < 0)
	dns_error(0,"create worker");
 if(create_author(s,s->nquizzer) < 0)
	dns_error(0,"create author");
 if(pthread_create(&pt,NULL,(void*)time_cron,s) != 0)
	dns_error(0,"time cron error");
 //pthread_mutex_lock(&s->ttlexp->lock);
 read_root(s->datasets,s->ttlexp);
 //pthread_mutex_unlock(&s->ttlexp->lock);
 print_basic_debug();
 run_sentinel(s);
 return 0;
}
