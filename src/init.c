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
#include "update.h"
#include "config.h"
#include "memory.h"
#include <sys/time.h>
#include <assert.h>
#include <signal.h>

//----------------------------------------------
time_t global_now = 0;
pthread_mutex_t gnlock;
volatile sig_atomic_t refresh_record = 0;
//----------------------------------------------


extern int daemon(int, int);
struct entry;


static int
daemonrize(int dm)
{
    if (dm == 1) {
        if (daemon(1, 0) == -1)
            dns_error(0, "daemonrize");
        else
            printf("daemon!!!\n");      //we will never see this
    }
    return 0;
}


static int
create_listen_ports(int port, int proto, uchar * addr)
{
    int fd = -1;
    fd = create_socket(port, proto, addr);
    if (fd < 0 || set_non_block(fd) < 0) {
        printf("port:%d,proto:%d\n", port, proto);
        dns_error(0, "fd < 0");
    }
    return fd;
}


int
create_author(struct server *s, int n)
{
    int i, j;
    struct author *authors = NULL;
    cpu_set_t cpuinfo;
    pthread_t apt[QUIZZER_NUM];
    if (n < 1 || n > 50)
        dns_error(0, "quizzer bad range");
    if ((authors = malloc(sizeof(struct author) * n)) == NULL)
        dns_error(0, "out of memory in quizzer");
    memset(authors, 0, sizeof(struct author) * n);
    s->authors = authors;
    for (i = 0; i < n; i++) {
        authors[i].idx = i;
        authors[i].cudp = s->ludp;
        authors[i].audp = create_listen_ports(i * 1000 + 998, UDP, NULL);
        if (authors[i].audp < 0)
            dns_error(0, "auth fd error");
        set_sock_buff(authors[i].audp, 1);
        authors[i].el = &s->eventlist;
        authors[i].s = s;
        get_random_data(authors[i].randombuffer, RANDOM_SIZE);
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
        authors[i].qidx = 0;    //start idx in qoutinfo list
        authors[i].start = QLIST_TABLE_SIZE / QUIZZER_NUM * i;
        if (i == (QUIZZER_NUM - 1))
            authors[i].end = QLIST_TABLE_SIZE;
        else
            authors[i].end = QLIST_TABLE_SIZE / QUIZZER_NUM * (i + 1);
        memset(authors[i].ip, 0, IP_DATA_LEN);
        authors[i].loginfo = malloc(sizeof(struct log_info));
        memset(authors[i].loginfo, 0, sizeof(struct log_info));
        authors[i].loginfo->log_type = TYPE_QUIZZER;
        authors[i].loginfo->logfd = create_new_log(s->logpath, i, TYPE_QUIZZER);
        for (j = 0; j < AUTH_DB_NUM; j++)
            pthread_spin_init(&(authors[i].dblock[j]), 0);
        for (j = 0; j < LIST_SPACE; j++)
            authors[i].list[j] = NULL;
        for (j = 0; j < EP_TCP_FDS; j++)
            authors[i].eptcpfds[j].ret = -1;
        pthread_spin_init(&authors[i].lock, 0);
        authors[i].loginfo->lastlog = global_now;
        if (authors[i].cudp < 0 || authors[i].audp < 0)
            dns_error(0, "create quizzer2");
        if (pthread_create(apt + i, NULL, run_quizzer, (void *) &(authors[i]))
            != 0)
            dns_error(0, "create quizzer");
    }
    global_out_info->thread_num += i;
    
    for(i = 0;i < QUIZZER_NUM ;i ++)
    {
        CPU_ZERO(&cpuinfo);
        CPU_SET_S(i + FETCHER_NUM + 1, sizeof(cpuinfo), &cpuinfo);
        if(0 != pthread_setaffinity_np(apt[i], sizeof(cpu_set_t), &cpuinfo))
        {
            printf("set affinity quizzer failed, may be the cpu cores num less than (FETCHER_NUM + QUIZZER_NUM + 1)\n");
//             exit(0);
        }
    }
    
    return 0;
}


static int
create_fetcher(struct server *s, int n)
{
    int i;
    struct fetcher *ws, *tmp;
    cpu_set_t cpuinfo;
    pthread_t fpt[FETCHER_NUM];
    if (n < 1)
        return -1;
    ws = malloc(sizeof(struct fetcher) * n);    //associated a worker with main thread
    if (ws == NULL)
        return -1;
    memset(ws, 0, sizeof(struct fetcher) * n);
    s->fetchers = ws;
    for (i = 0; i < n; i++) {
        tmp = ws + i;
        tmp->s = s;
        tmp->idx = i;
        tmp->pkg = 0;
        tmp->send = 0;
        tmp->miss = 0;
        tmp->el = &s->eventlist;
        tmp->qidx = i % QUIZZER_NUM;
        tmp->mc = init_msgcache(100);
        if (tmp->mc == NULL)
            dns_error(0, "get msgcache");
        tmp->loginfo = malloc(sizeof(struct log_info));
        memset(tmp->loginfo, 0, sizeof(struct log_info));
        tmp->loginfo->lastlog = global_now;
        tmp->loginfo->log_type = TYPE_FETCHER;
        tmp->loginfo->logfd = create_new_log(s->logpath, i, TYPE_FETCHER);
        if (tmp->loginfo->logfd < 0)
            dns_error(0, "log file error");
        if (pthread_create(fpt + i, NULL, (void *) run_fetcher, tmp) != 0)
            dns_error(0, "init worker");
    }
    global_out_info->thread_num += i;
    
    for(i = 0;i < FETCHER_NUM ;i ++)
    {
        CPU_ZERO(&cpuinfo);
        CPU_SET_S(i + 1, sizeof(cpuinfo), &cpuinfo);
        if(0 != pthread_setaffinity_np(fpt[i], sizeof(cpu_set_t), &cpuinfo))
        {
            printf("set affinity fetcher failed,  may be the cpu cores num less than (FETCHER_NUM + QUIZZER_NUM + 1)\n");
//             exit(0);
        }
    }
    
    return 0;
}


static struct server *
server_init(void)
{
    struct server *s = malloc(sizeof(struct server));
    if (s == NULL)
        dns_error(0, "out of memory in server_init");
    s->nfetcher = FETCHER_NUM;
    s->nquizzer = QUIZZER_NUM;
    s->authors = NULL;
    s->fetchers = NULL;
    s->pkg = 0;
    pthread_spin_init(&s->eventlist.lock, 0);
    //pthread_mutex_init(&s->lock,NULL);
    s->eventlist.head = NULL;
    if ((s->ludp = create_listen_ports(SERVER_PORT, UDP, (uchar *)SRV_ADDR)) < 0)
        dns_error(0, "can not open udp");
    set_sock_buff(s->ludp, 10);
    if ((s->ltcp = create_listen_ports(SERVER_PORT, TCP, (uchar *)SRV_ADDR)) < 0)
        dns_error(0, "can not open tcp");
    s->datasets =
        htable_create(NULL, dict_comp_str_equ, HASH_TABLE_SIZE,
                      MULTI_HASH);
    if (s->datasets == NULL)
        dns_error(0, "htable create");
    s->forward = htable_create(NULL, dict_comp_str_equ, 1024, 1);
    if (s->forward == NULL)
        dns_error(0, "create forward");
    s->qlist =
        htable_create(NULL, dict_comp_str_equ,
                      QLIST_TABLE_SIZE, 1);
    if (s->qlist == NULL)
        dns_error(0, "create qlist");
    s->ttlexp = create_rbtree(rbt_comp_ttl_gt, NULL);
    if (s->ttlexp == NULL)
        dns_error(0, "create ttl tree");
    s->recordsindb = 0;
    s->refreshflag = 0;
    s->lastrefresh = global_now;
    s->is_forward = 0;
    return s;
}


void *
time_cron(void *arg)
{
    struct server *s = (struct server *) arg;
    struct timespec tv = { 0 };
    sigset_t waitset;
    siginfo_t info;
    int ret;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIGUSR1);
//     pthread_mutex_init(&gnlock, NULL);
    global_now = time(NULL);
    while (1) {
        tv.tv_sec = 1;
        tv.tv_nsec = 0;
        ret = sigtimedwait(&waitset, &info, &tv);
        if (ret > 0)
            s->refreshflag = 1;
//         pthread_mutex_lock(&gnlock);
//         global_now++;
//         pthread_mutex_unlock(&gnlock);
        //printf("time %lu\n",global_now);
//         if ((global_now % 100) == 0) {
//             pthread_mutex_lock(&gnlock);
            global_now = time(NULL);
//             pthread_mutex_unlock(&gnlock);
//         }
    }
    return NULL;
}

void *
recv_update(void *arg)
{
    struct server *s = (struct server *)arg;
    start_local_server(s);
    return NULL;
}

int
sanity_test(int exi)
{
    //rbtree_test();
    if (exi)
        exit(0);
    return 0;
}


int
print_basic_debug(void)
{
    printf("[DBG:] dnspod-sr is successful running now!!\n");
    printf("[DBG:] max_ele_size is %u - 1808\n", MAX_ELE_NUM);
    printf("[DBG:] server may contain %u useful records\n",
            (MAX_ELE_NUM - 1808) / 3);
    printf("[DBG:] hash_table_size is %u\n", HASH_TABLE_SIZE);
    printf("[DBG:] we have %u hash tables\n", MULTI_HASH);
    printf("[DBG:] we have %u fetchers,%u quizzers\n", FETCHER_NUM,
            QUIZZER_NUM);
    return 0;
}


void
help(const char *progname)
{
    printf("DNSPod recursive dns server\n");
    printf("version 0.01\n");
    printf("Usage: %s [-c config]\n", progname);
}

int init_globe()
{
    int shmid;
    shmid = shmget(SHM_KEY, sizeof(struct global_query_info), IPC_CREAT|0600|IPC_PRIVATE);
    if (shmid < 0) {
        printf("%lu\n", SHM_KEY + sizeof(struct global_query_info));
        perror("shmget");
        dns_error(0, "shmget error");
    }
    global_out_info = (struct global_query_info *)shmat(shmid, NULL, 0);
    memset(global_out_info, 0, sizeof(struct global_query_info));
    global_out_info->thread_num = 0;
    int i;
    for (i = 0; i < sizeof(query_type_map) / sizeof(int); ++i)
    {
        query_type_map[i] = -1;
    }
    query_type_map[A] 		=  0;
    query_type_map[NS] 		=  1;
    query_type_map[CNAME] 	=  2;
    query_type_map[SOA] 	=  3;
    query_type_map[MX] 		=  4;
    query_type_map[TXT] 	=  5;
    query_type_map[AAAA] 	=  6;
    query_type_map[SRV] 	=  7;
    query_type_map[ANY] 	=  8;
    return 0;
}

void init_mempool()
{
    int ret;
    ret = mempool_create(MEMPOOL_SIZE);
    if (ret < 0)
        dns_error(0, "create mempool failed");
}

int
main(int argc, char **argv)
{
    struct server *s = NULL;
    pthread_t pt, ctl;
    int c, is_forward = 0;
    const char *config = SR_CONFIG_FILE;
    int daemon = 0;
    while ((c = getopt(argc,argv,"c:vhfd")) != -1)
    {
        switch(c)
        {
            case 'c':
                config = optarg;
                break;
            case 'h':
                help(argv[0]);
                exit(0);
                break;
            case 'f':
                is_forward = 1;
                break;
            case 'd':
                daemon = 1;
                break;
            case '?':
                printf("Try -h please\n");
                exit(0);
                break;
            case 'v':
                printf("dnspod-sr 0.01\n");
                exit(0);
                break;
            default:
                exit(0);
                break;
        }
    }
    sanity_test(0);
    drop_privilege("./");
    daemonrize(daemon);
    trig_signals(1);
    global_now = time(NULL);    //for read root.z
    g_nameservers[0] = g_nameservers[1] = NULL;
    init_globe();
    init_mempool();
    s = server_init();
    s->is_forward = is_forward;
    read_config(config, (char *)s->logpath, s->forward, g_nameservers);
    // add default dns server 8.8.8.8, 114.114.114.114
    if (g_nameservers[0] == NULL) {
        assert(g_nameservers[1] == NULL);
        g_nameservers[0] = strdup("8.8.8.8");
        g_nameservers[1] = strdup("8.8.4.4");
    }
    if (g_nameservers[1] == NULL) {
        if (strcmp(g_nameservers[0], "8.8.8.8") == 0) {
            g_nameservers[1] = strdup("8.8.4.4");
        } else {
            g_nameservers[1] = strdup("8.8.8.8");
        }
    }
    //
    if (create_fetcher(s, s->nfetcher) < 0)
        dns_error(0, "create worker");
    if (create_author(s, s->nquizzer) < 0)
        dns_error(0, "create author");
    if (pthread_create(&pt, NULL, (void *) time_cron, s) != 0)
        dns_error(0, "time cron error");
    if (pthread_create(&ctl, NULL, (void *)recv_update, s) != 0) {
        dns_error(0, "recv update thread error");
    }
    read_root(s->datasets, s->ttlexp);
    print_basic_debug();
    global_serv = s;
    run_sentinel(s);
    return 0;
}
