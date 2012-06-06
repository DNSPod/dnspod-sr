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


#include "author.h"


//get random number from a buffer
//it's faster than invoke function random every time
//no lock, author use it's own data
int
get_random_int_from_author(struct author *author)
{
    int val = 0;
    char *ret = NULL;
    if (author->rndidx + sizeof(int) >= RANDOM_SIZE) {
        //read from /dev/urandom
        get_random_data(author->randombuffer, RANDOM_SIZE);
        author->rndidx = 0;
    }
    val = *(int *) (author->randombuffer + author->rndidx);
    author->rndidx += sizeof(int);
    return val;
}


//for tcp
//add to list, sentinel will delete this in the main event loop
int
delete_close_event(int fd, struct fetcher *f)
{
    struct list *el = NULL;
    struct list_node *nd = NULL;
    el = f->el;
    if (el == NULL)
        return -1;
    if ((nd = malloc(sizeof(struct list_node))) == NULL)
        return -1;
    nd->data = malloc(sizeof(int));
    if (nd->data == NULL) {
        free(nd);
        return -1;
    }
    memcpy(nd->data, &fd, sizeof(int));
    pthread_mutex_lock(&el->lock);
    nd->next = el->head;
    el->head = nd;
    pthread_mutex_unlock(&el->lock);
    return 0;
}


int
send_msg_to_client(struct sockinfo *cli, uchar * td, ushort id,
                   uchar * msg)
{
    struct mvalue *mv = NULL;
    uchar *itor = NULL;
    dnsheader *hdr = NULL;
    uint32_t *pttl = NULL, ttl = 0;
    uint16_t *pttloff = NULL;
    int i;
    uchar msgbuf[65536] = { 0 };
    itor = msg + 1;             //databuffer format
    //type.mvalue.msg
    mv = (struct mvalue *) itor;
    itor += sizeof(struct mvalue);      //jump mvalue
    pttloff = (uint16_t *) itor;
    itor += mv->seg * sizeof(uint16_t); //jump ttloff
    cli->buf = itor;
    cli->buflen = mv->len;
    hdr = (dnsheader *) itor;
    hdr->id = id;
    ttl = mv->ttl - global_now;
    ttl = htonl(ttl);
    for (i = 0; i < mv->seg; i++) {
        pttl = (uint32_t *) (itor + pttloff[i]);
        *pttl = ttl;
    }
    //printf("msg:%u\n",mv->len);
    //for(i = 0;i < mv->len;i ++)
    //printf("%x,",itor[i]);
    //printf("\n");
    //////////////////////////////////////////////////////
    if (cli->socktype == UDP) {
        if (mv->len > MAX_UDP_SIZE)
            send_tc_to_client(td, cli, id);
        else
            udp_write_info(cli, 0);     //ignore send error
    } else {
        //first two bytes are length of msg
        memcpy(msgbuf + 2, itor, mv->len);
        *(ushort *) msgbuf = htons(mv->len);
        cli->buflen = mv->len + 2;
        cli->buf = msgbuf;
        tcp_write_info(cli, 0);
    }
    return 0;
}


//databuffer format
//type.mvalue.data.type.mvalue.data...
int
write_back_to_client(uchar * msgto, uchar * td, ushort id, int dlen,
                     struct sockinfo *cli, uchar * fr, int vlen)
{
    struct setheader sh = { 0 };        //data in dns header
    int i, num = 0, main = 0, dnslen = 0;
    uchar msg[1000] = { 0 }, type;      //if bigger, use TCP
    uchar *from = fr, *to = msg + 2, *tag;
    struct mvalue *mv = NULL;
    int jump = 0, msglen = 512, ret;
    uint16_t ttloff[MAX_MSG_SEG + 1] = { 0 };   //zero ele is idx
    struct hlpc hlp[200] = { 0 };       //p domians to compression
    hlp[0].name = td + 1;
    hlp[0].off = sizeof(dnsheader);
    hlp[0].level = get_level(hlp[0].name);
    hlp[0].ref = -1;
    hlp[0].mt = 0;
    jump = sizeof(dnsheader) + dlen + sizeof(qdns);
    to = to + jump;
    while (vlen > 1)            //vlen include type.mvalue.data.
    {
        type = from[0];
        mv = (struct mvalue *) (from + 1);
        to = fill_rrset_in_msg(hlp, from, to, main, msg + 2, ttloff);
        if (to == NULL)
            return -1;
        vlen = vlen - 1 - mv->len - sizeof(struct mvalue);
        sh.an += mv->num;
        if (type == CNAME)      //cname must be 1
            main++;             //no all rdata is the cname's
        from = from + mv->len + 1 + sizeof(struct mvalue);      // type.mv.len.
    }
    sh.itor = msg + 2;
    sh.od = td + 1;
    sh.id = id;
    sh.type = td[0];
    fill_header_in_msg(&sh);
    dnslen = to - (msg + 2);
    cli->buf = msg + 2;
    cli->buflen = dnslen;
    if (cli->socktype == UDP) {
        if (dnslen > MAX_UDP_SIZE)
            send_tc_to_client(td, cli, id);
        else
            udp_write_info(cli, 0);     //ignore send error
    } else {
        *(ushort *) msg = htons(dnslen);
        cli->buflen = dnslen + 2;
        cli->buf = msg;
        tcp_write_info(cli, 0);
    }
    ////////////////////////////////////////////////////////////
    //key, val, vallen, ttl offset
    //if now + TTL_UPDATE > ttl
    //return
    ret = transfer_record_to_msg(msgto, td, msg + 2, dnslen, ttloff);
    if (ret < 0)
        return -1;
    return 0;
}


//process a segment of data
int
passer_related_data(struct sockinfo *si, struct qoutinfo *qo,
                    struct author *author)
{
    uchar *buf = si->buf, *tail = NULL;
    int len = sizeof(struct sockaddr_in), stype = 0, ret, seg;
    uint idx = 0;
    uchar dms[50 * DMS_SIZE] = { 0 };
    struct rbtree *rbt;
    int datalen = 0, debugu = 0, i, tag;
    uchar *tmptail, xtag;
    ushort n, type, class;
    struct hlpp hlp;
    dnsheader *hdr = (dnsheader *) buf;
    ret = check_dns_name(buf + sizeof(dnsheader), &seg);
    if (ret < 0)
        return -1;
    if (check_domain_mask(buf + sizeof(dnsheader), qo->qing) < 0)
        return -1;
    hlp.dmsidx = 1;
    memcpy(dms, qo->qing, strlen(qo->qing) + 1);
    tail = buf + sizeof(dnsheader) + ret;       //domain len
    type = ntohs(*(ushort *) tail);
    class = ntohs(*(ushort *) (tail + 2));
    tail = tail + 4;
    datalen = si->buflen;
    rbt = author->s->ttlexp;
    n = ntohs(hdr->ancount);
    hlp.stype = &stype;
    hlp.ds = author->s->datasets;
    hlp.rbt = rbt;
    hlp.buf = buf;
    hlp.datalen = datalen;
    hlp.dms = dms;
    if (n > 0) {
        hlp.section = AN_SECTION;
        tail = process_rdata(&hlp, tail, n);
        if (tail == NULL)
            return -1;
    }
    n = ntohs(hdr->nscount);
    if (n > 0) {
        hlp.section = NS_SECTION;
        tail = process_rdata(&hlp, tail, n);
        if (tail == NULL)
            return -1;
    }
    n = ntohs(hdr->arcount);
    if (n > 0) {
        hlp.section = AR_SECTION;
        tail = process_rdata(&hlp, tail, n);
        if (tail == NULL)
            return -1;
    }
    return stype;
}


int
send_msg_tcp(struct author *author, int fd)
{
    struct qoutinfo *qo = NULL;
    ushort id, type;
    uchar buffer[512] = { 0 };
    int len, i, st = 0, ret;
    struct sockinfo si;
    ret = author->eptcpfds[fd];
    if (ret <= 0)
        return -1;
    qo = author->list[ret];
    if (qo == NULL)
        return -1;
    id = qo->aid;
    type = qo->td[0];
    if (qo->qname == Q_NS)
        type = A;
    len = make_dns_msg_for_new(buffer + 2, id, qo->qing, type);
    *(ushort *) buffer = htons(len);
    si.fd = fd;
    si.buf = buffer;
    si.buflen = len + 2;
    tcp_write_info(&si, 0);
    return 0;
}


//connect to server, tcp is expensive, we use 1 addr once
//do connect thing
//send thing will be done in cb_read_callback xxxx
int
query_from_auth_tcp(struct author *author, struct qoutinfo *qo)
{
    struct sockinfo si;
    int addridx = 0, i, st = 0;
    uchar *ip = author->ip;
    struct mvalue *mv = NULL;
    mv = (struct mvalue *) ip;
    while (mv->num > 0) {
        ip += sizeof(struct mvalue);
        for (i = 0; i < mv->num; i++) {
            if (st == (qo->tcpnums - 1)) {
                si.fd = qo->tcpfd;
                make_addr_from_bin(&(si.addr), ip);
                si.addr.sin_port = htons(53);
                si.addr.sin_family = AF_INET;
                connect_to(&si);
                st = MOST_TRY_PER_QUERY + 1;    //break while
            }
            st++;
        }
        ip += mv->len;
        mv = (struct mvalue *) ip;
        if (st > MOST_TRY_PER_QUERY)
            break;
    }
    return 0;
}


int
query_from_auth_server(struct qoutinfo *qo, struct author *author)
{
    ushort id = qo->aid, type;
    uchar buffer[512] = { 0 };
    uchar *ip = author->ip;
    int len, i, st = 1, ret;
    int maxtry = 0;
    struct mvalue *mv = NULL;
    struct sockinfo si;
    struct sockaddr_in addr;
    type = qo->td[0];
    //dbg_print_td(qo->td);
    if (qo->qname == Q_NS)
        type = A;
    qo->mxtry++;
    if (qo->socktype == UDP) {
        len = make_dns_msg_for_new(buffer, id, qo->qing, type);
        si.buf = buffer;
        si.buflen = len;
        si.fd = author->audp;
        mv = (struct mvalue *) ip;
        while (mv->num > 0) {
            ip += sizeof(struct mvalue);
            for (i = 0; i < mv->num; i++) {
                make_addr_from_bin(&(si.addr), ip + i * 4);     //ipv4 only
                //dbg_print_addr((struct sockaddr_in*)&(si.addr));
                si.addr.sin_port = htons(53);
                ret = udp_write_info(&si, 0);
                if (ret > 0)    //success
                    st++;
                if (st > qo->mxtry)
                    return 0;
            }
            ip += mv->len;
            mv = (struct mvalue *) ip;
            if (st > MOST_TRY_PER_QUERY)
                break;
        }
    }
    return 0;
}


//udpate id, later msg will be droped
static int
update_id(struct qoutinfo *qo)
{
    if (qo->aid + LIST_SPACE > ID_SPACE)
        qo->aid = qo->aid % LIST_SPACE;
    else
        qo->aid = qo->aid + LIST_SPACE;
    qo->backid = qo->aid;
    qo->sq = 1;
    return 0;
}


//clear the querying bit, free struct
int
release_qoutinfo(struct author *author, int idx)
{
    int fd = -1, epfd, ret;
    struct qoutinfo *qo = NULL;
    struct epoll_event ev;
    struct htable *qlist = NULL;
    qo = author->list[idx];
    epfd = author->bdepfd;
    qlist = author->s->qlist;
    if (qo == NULL)
        return -1;
    fd = qo->tcpfd;
    ev.data.fd = fd;
    if (fd > 0) {
        author->tcpinuse--;
        ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
        author->eptcpfds[fd] = 0;
        close(fd);
    }
    if (qo->cli)
        free(qo->cli);
    htable_delete(qlist, qo->td);
    free(qo->td);               //malloced by lock_ad_ad_t_qzer.
    free(qo);
    return 0;
}


int
init_qoutinfo(struct qoutinfo *qo)
{
    qo->socktype = UDP;
    qo->mxtry = 0;
    qo->qns = 1;                //default query ns.
    qo->sq = 1;                 //default send query
    return 0;
}


//-1 error
//-2 tc
//0 continue
//1 normal
int
check_enter(struct author *author, uchar * buf, int *idx, int len)
{
    ushort id;
    int off, ret;
    int tx = 0;
    struct qoutinfo *qo = NULL;
    dnsheader *hdr = (dnsheader *) buf;
    id = hdr->id;
    off = id % LIST_SPACE;
    qo = author->list[off];
    if (qo == NULL || (qo->aid != id))
        return 0;               //late
    *idx = off;
    //-1 error
    //1  tc
    //0 normal
    //2 retry
    ret = check_an_msg(hdr->flags, NULL, &tx);
    if (ret < 0)
        return -1;              //error
    if (ret == 1)               //tc
        return -2;
    if ((ret == 2) && (tx == 1))        //server error ,continue
        return -3;
    qo->socktype = UDP;         //default
    return 1;
}


//return 0,continue
//return idx > 0,delete and release qoutinfo
//return < 0,error,nothing
//0 is a valid idx,but it has a special meaning.
//so we return idx + 1. and use it minus 1
int
passer_auth_data(struct author *author, uchar * buf, struct sockinfo *si)
{
    int idx, ret, pret, xret;
    uchar td[256] = { 0 }, *val = NULL, *itor = NULL;
    uint16_t mblen = 0, hash;
    struct qoutinfo *qo = NULL;
    ushort xtype = 0;
    dnsheader *hdr = (dnsheader *) buf;
    struct mvalue *mvp = NULL, *mv = NULL, mx;
    struct sockaddr_in *addr = NULL;
    //msg buffer
    uchar mb[MAX_MSG_SIZE + sizeof(uint16_t)] = { 0 };
    ret = check_enter(author, buf, &idx, si->buflen);
    //we get tc and do NOT update id
    //because some bad servers always return tc
    //thus we has chance to get another answers
    //then close tcp immediately, and send nothing
    if (ret == -2)              //tc,use tcp.
        return -idx - 1;
    if (ret == 0)               //late msg,server refused,continue
        return 0;
    if (ret == -1)              //error msg, delete qoutinfo
        return idx + 1;
    qo = author->list[idx];
    qo->mxtry--;
    if (ret == -3)              //format error, server refused, error...
    {
        qo->qtimes++;
        return 0;
    }
    pret = passer_related_data(si, qo, author);
    if (pret < 0)
        return 0;               //error msg,continue
    update_id(qo);
    if (pret == CNAME && qo->td[0] == CNAME) {
        if (qo->cli != NULL) {
            *(ushort *) buf = qo->cid;
            qo->cli->buf = buf;
            qo->cli->buflen = si->buflen;
            if (si->buflen > MAX_UDP_SIZE)
                send_tc_to_client(qo->td, qo->cli, qo->cid);
            else {
                udp_write_info(qo->cli, 0);     //cname..
                write_log(&author->logfd, &author->lastlog, author->idx,
                          qo->td + 1, qo->td[0], &qo->cli->addr);
            }
        }
        return idx + 1;
    }
    if (pret == CNAME || qo->qname != Q_DOMAIN) {
        qo->stat = PROCESS_QUERY;
        qo->socktype = UDP;     //if prev we use tcp, use udp again
        return 0;
    }
    if ((pret == SOA) || (ntohs(hdr->ancount) > 0)) {
        if (qo->cli != NULL) {
            if (qo->hascname == 0) {
                *(ushort *) buf = qo->cid;      //no need to htons
                qo->cli->buf = buf;
                qo->cli->buflen = si->buflen;
                if (si->buflen > MAX_UDP_SIZE)
                    send_tc_to_client(qo->td, qo->cli, qo->cid);
                else {
                    udp_write_info(qo->cli, 0);
                    write_log(&author->logfd, &author->lastlog,
                              author->idx, qo->td + 1, qo->td[0],
                              &qo->cli->addr);
                }
            } else              //has a cname,put the origin domain first
            {
                if (pret == SOA) {
                    xtype = qo->td[0];
                    qo->td[0] = CNAME;
                }
                ret =
                    find_record_from_mem(qo->td, qo->dlen,
                                         author->s->datasets,
                                         author->databuffer);
                if (pret == SOA)
                    qo->td[0] = xtype;
                if (ret > 0) {
                    mv = (struct mvalue *) (author->databuffer + 1);
                    author->response++;
                    if (qo->cli) {
                        xret =
                            write_back_to_client(mb, qo->td, qo->cid,
                                                 qo->dlen, qo->cli,
                                                 author->databuffer, ret);
                        if (xret == 0) {
                            mvp = (struct mvalue *) mb;
                            val =
                                malloc(mvp->len + sizeof(struct mvalue) +
                                       mvp->seg * sizeof(uint16_t));
                            if (val != NULL) {
                                memcpy(val, mb, sizeof(struct mvalue));
                                mvp = (struct mvalue *) val;
                                mvp->ttl = mv->ttl;
                                mvp->hits = mv->hits;
                                mvp->num = 0;   //not used
                                itor = val + sizeof(struct mvalue);
                                //copy ttloff and msg
                                memcpy(itor, mb + sizeof(struct mvalue),
                                       sizeof(uint16_t) * mvp->seg +
                                       mvp->len);
                                hash = get_pre_mem_hash(qo->td);
                                htable_insert(author->s->datasets + hash, qo->td, val, 1, &mx); //replace
                            }
                            addr = &(qo->cli->addr);
                        }
                    }
                    write_log(&author->logfd, &author->lastlog,
                              author->idx, qo->td + 1, qo->td[0], addr);
                }
            }
        }
        //else printf("update record\n");
        return idx + 1;
    }
    qo->stat = PROCESS_QUERY;   //no need to find_addr in launch_new_qu
    qo->socktype = UDP;
    return 0;
}


//read from auth server
int
cb_read_auth(struct epoll_event *ev, struct sockinfo *si)
{
    int ret, tag = 1, szhdr = sizeof(dnsheader);
    si->fd = ev->data.fd;
    si->buflen = BIG_MEM_STEP - 2;
    if (si->socktype == TCP)
        ret = tcp_read_dns_msg(si, BIG_MEM_STEP - 2, 0);
    else
        ret = udp_read_msg(si, 0);      //epoll return and no blocked here
    if (ret < szhdr)
        return -1;
    si->buflen = ret;
    return ret;
}


int
launch_new_query(struct author *author, int idrowback)
{
    const int querystep = 200;
    int new_query = 0, i, start, end, ret;
    struct qoutinfo *qo = NULL;
    uchar *itor = NULL;
    struct timeval tv;
    uint msnow = 0;
    struct mvalue *mv = NULL;
    start = 0;
    end = LIST_SPACE;
    gettimeofday(&tv, NULL);
    for (i = start; i < end; i++) {
        pthread_mutex_lock(&author->lock);
        if (author->list[i] != NULL
            && author->list[i]->qtimes > MAX_TRY_TIMES) {
            release_qoutinfo(author, i);
            author->list[i] = NULL;
        }
        if (author->list[i] != NULL) {
            pthread_mutex_unlock(&author->lock);
            qo = author->list[i];
            if (author->list[i]->stat == NEW_QUERY)     //new
            {
                qo->aid = idrowback * LIST_SPACE + i;   //start id
                qo->backid = qo->aid;
                qo->mxtry = 0;
                if (qo->cli)
                    qo->cli->fd = author->cudp;
                new_query++;
                qo->stat = PROCESS_QUERY;
            }
            if ((msnow - qo->stime) > 1000 && (qo->sq == 0))
                qo->sq = 1;
            if ((qo->socktype == UDP) && (qo->sq == 1)) {
                ret =
                    find_addr(author->s->forward, author->s->datasets, qo,
                              author->ip);
                if (qo->stat == PROCESS_QUERY && ret == 0)
                    query_from_auth_server(qo, author);
                qo->qtimes++;
                qo->stime = msnow;
            }
        } else
            pthread_mutex_unlock(&author->lock);
    }
    return new_query;
}


int
after_pass_data(int ret, struct author *author)
{
    struct rbnode *pn;
    struct epoll_event ev;
    struct qoutinfo *qo = NULL;
    int i, idx, fd;
    if (ret == 0)
        return 0;
    if (ret < 0)                //tcp needed.
    {
        //printf("tcp needed\n");
        ret = ret + 1;
        ret = -ret;
        qo = author->list[ret];
        if (qo == NULL)
            return -1;
        if ((qo->tcpfd > 0) && ((qo->qtimes % (MAX_TRY_TIMES / 3)) == 0))       //retry tcp
        {
            ev.data.fd = qo->tcpfd;
            qo->tcpfd = 0;
            author->tcpinuse--;
            epoll_ctl(author->bdepfd, EPOLL_CTL_DEL, ev.data.fd, &ev);
            close(ev.data.fd);
        }
        if (qo->tcpfd > 0)      //processing...
            return 0;
        //restart..
        if (author->tcpinuse > (LIST_SPACE / 10))
            fd = -1;            //too many tcps
        else {
            qo->tcpnums++;
            fd = socket(AF_INET, SOCK_STREAM, 0);
        }
        if (fd > 0) {
            author->tcpinuse++;
            qo->tcpfd = fd;
            qo->socktype = TCP;
            ev.data.fd = fd;
            ev.events = EPOLLOUT;       //wait for ready to write
            author->eptcpfds[fd] = ret;
            set_non_block(fd);
            set_recv_timeout(fd, 0, 500);       //half second
            epoll_ctl(author->bdepfd, EPOLL_CTL_ADD, fd, &ev);
            query_from_auth_tcp(author, qo);
            return 0;
        } else
            ret++;              //fix ret value, for deleting afterword
    }

    if (ret > 0)                //delete qoutinfo
    {
        ret = ret - 1;          //minus the 1 p_a_d added
        pthread_mutex_lock(&author->lock);
        release_qoutinfo(author, ret);
        if (author->list[ret] != NULL) {
            author->list[ret] = NULL;
            author->qnum--;
        }
        pthread_mutex_unlock(&author->lock);
    }
    return 0;
}



int
handle_back_event(struct author *author)
{
    int infinite = 1, ret, i, epfd = author->bdepfd;
    struct sockinfo si = { 0 };
    int bf = 0, record = 0, rx;
    struct epoll_event ev, e[BACK_EVENT] = { 0 };
    uchar buf[BIG_MEM_STEP] = { 0 };
    while (1 && infinite) {
        bf = author->audp;
        ret = epoll_wait(epfd, e, BACK_EVENT, 500);     // 1000 is 1s
        if (ret <= 0)
            break;
        for (i = 0; i < ret; i++) {
            si.buf = buf;
            if (e[i].data.fd == bf) {
                si.socktype = UDP;
                while (cb_read_auth(e + i, &si) > 0) {
                    rx = passer_auth_data(author, buf, &si);
                    after_pass_data(rx, author);
                }
            } else if (e[i].data.fd > 0)        //  fd 0 will be ignored
            {
                if (e[i].events == EPOLLOUT)    //ready to write
                {
                    rx = send_msg_tcp(author, e[i].data.fd);
                    if (rx < 0)
                        printf("send msg tcp error\n");
                    ev.data.fd = e[i].data.fd;
                    ev.events = EPOLLIN;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, e[i].data.fd, &ev);
                } else if (e[i].events == EPOLLIN) {
                    si.socktype = TCP;
                    rx = cb_read_auth(e + i, &si);
                    if (rx < 0) {
                        author->eptcpfds[e[i].data.fd] = 0;
                        close(e[i].data.fd);
                        ev.data.fd = e[i].data.fd;
                        epoll_ctl(epfd, EPOLL_CTL_DEL, ev.data.fd, &ev);
                    } else {
                        rx = passer_auth_data(author, buf, &si);
                        after_pass_data(rx, author);
                    }
                } else          //error
                {
                    //we do not handle the fail condition
                    //just delete it from epoll and close it
                    //EPOLLIN = 0x001,
                    //EPOLLPRI = 0x002,
                    //EPOLLOUT = 0x004,
                    //EPOLLERR = 0x008,
                    //EPOLLHUP = 0x010,
                    ev.data.fd = e[i].data.fd;
                    rx = epoll_ctl(epfd, EPOLL_CTL_DEL, e[i].data.fd, &ev);
                    author->eptcpfds[e[i].data.fd] = 0;
                    close(e[i].data.fd);
                    //printf("epoll fd=%d,events=0x%x,rx=%d\n",e[i].data.fd,e[i].events,rx);
                }
            }
        }
    }
    return 0;
}


//when a record is queried and its not in memory
//we load it from disk, and not add it to memory
//when it's ttl is expired, it will be deleted in disk
//and when it not hited in disk, we query data from
//auth server, then store record in memory
int
dup_data_into_db(struct author *a)
{
    uint i, hits = 10, hs, limit;
    //static uint dbidx = 0,dboff = 0;
    uchar buffer[2000] = { 0 };
    uchar key[514] = { 0 };
    int ret, dupx = 0;
    time_t now;
    struct rbnode *pn = NULL;
    struct rbtree *rbt = a->s->ttlexp;
    uint num, dboff, dbidx, slotoff, imgidx = 0;
    struct hentry *he;
    uchar *val = NULL;
    struct mvalue *mv = NULL, tmp;
    struct ttlnode tn, *ptn;
    now = global_now;
    if (a->dupbefore == 1) {
        a->limits += 5;
        if (a->limits > 1000)
            a->limits = 1000;
    }
    limit = a->limits;
    //printf("dup start %d\n",a->limits);
    a->hsidx++;
    if (a->hsidx == MULTI_HASH)
        a->hsidx = 0;
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        dbidx = i;
        dboff = a->hsidx;
        slotoff = 0;
        ret =
            htable_find_io(a->s->datasets + dboff, dbidx, slotoff, buffer,
                           key);
        while (ret > 0) {
            slotoff++;
            mv = (struct mvalue *) buffer;
            //if mv ttl near "now", it may has started "ttl update"
            //mv->ttl means ttl expired time
            //TTL_UPDATE is 3
            //if ttl was 12, now was 11, don't delete
            //if ttl was 12, now was 7, delete it
            if ((mv->ttl > (now + TTL_UPDATE + 1)) && (mv->hits < limit)) {
                he = htable_delete(a->s->datasets + dboff, key);
                if (he != NULL) {
                    tn.data = key;
                    tn.exp = mv->ttl;
                    tn.dlen = strlen(key) + 1;
                    pthread_mutex_lock(&rbt->lock);
                    pn = find_node(rbt, &tn);
                    if (pn != NULL) {
                        ptn = delete_node(rbt, pn);
                        if (ptn != NULL) {
                            //printf("delete true\n");
                            free(ptn->data);
                            free(ptn);
                        } else
                            printf("delete error\n");
                    } else {
                        printf("find error\n");
                        dbg_print_td(key);
                    }
                    pthread_mutex_unlock(&rbt->lock);
                    free(he->val);      //dup to disk do not need memory
                    free(he);
                }
                dupx++;
            }
            //else
            //printf("ttl %u,now %lu,hits %u\n",mv->ttl,now,mv->hits);
            ret =
                htable_find_io(a->s->datasets + dboff, dbidx, slotoff,
                               buffer, key);
        }
    }
    a->dupbefore = 1;
    return 0;
}


int
check_mm_cache(struct author *author)
{
    uint total = 0;
    int i;
    static int tmx = 0;
    for (i = 0; i < MULTI_HASH; i++) {
        pthread_mutex_lock(&author->s->datasets[i].lock);
        total += author->s->datasets[i].now;
        pthread_mutex_unlock(&author->s->datasets[i].lock);
    }
    tmx++;
    if (total > MAX_ELE_NUM)
        return 1;
    return 0;
}


int
check_ttl_expire(struct author *author)
{
    struct mvalue *mv = NULL, mx;
    time_t now;
    struct ttlnode *tn = NULL;
    struct rbnode *pn = NULL;
    struct qoutinfo qo = { 0 };
    struct htable *ds = NULL;
    int rnd = 0, ret = -1;
    struct rbtree *rbt = NULL;
    uint idx = 0;
    now = global_now;
    ds = author->s->datasets;
    rbt = author->s->ttlexp;
    pthread_mutex_lock(&rbt->lock);
    pn = min_node(rbt);
    while (pn != NULL) {
        tn = pn->key;
        //if exp was 12, now was 11, start
        //if exp was 12, now was 5, break
        if (tn->exp > (now + TTL_UPDATE))       //3 secs after it will not expire
            break;
        //dbg_print_td(tn->data);
        tn = delete_node(rbt, pn);
        pthread_mutex_unlock(&rbt->lock);
        if (tn != NULL) {
            //ret = find_record_with_ttl(ds,tn->data,NULL,0,&mx);
            //no buffer, if successed, ret would be 1 
            //if(ret > 0)
            {
                ret = htable_insert(author->s->qlist, tn->data, NULL, 0, NULL); //not replace
                if (ret == 0)   //we could insert more ttls of one same record
                {
                    qo.qname = tn->data[0];     //type
                    qo.td = tn->data;
                    qo.dlen = strlen(tn->data) + 1;
                    qo.qing = qo.td + 1;
                    qo.cid = 0;
                    qo.cli = NULL;
                    rnd = random() % QUIZZER_NUM;
                    init_qoutinfo(&qo);
                    if (add_to_quizzer(&qo, author->s, rnd) < 0)        //fail
                    {
                        //printf("add to quizzer error\n");
                        htable_delete(author->s->qlist, tn->data);
                    }
                } else
                    htable_insert(author->s->qlist, tn->data, NULL, 0,
                                  NULL);
            }
            //else querying lost
            free(tn);
        }
        pthread_mutex_lock(&rbt->lock);
        pn = min_node(rbt);
    }
    pthread_mutex_unlock(&rbt->lock);
    return 0;
}


int
check_refresh_flag(struct author *author)
{
    struct server *s = author->s;
    if ((s->lastrefresh + REFRESH_INTERVAL) > global_now)
        return 0;
    if (s->refreshflag == 1) {
        s->refreshflag = 0;
        s->lastrefresh = global_now;
        refresh_records(s->datasets, s->ttlexp);
    }
    return 0;
}


//main thread of query
//send query
//delete time outed
//recv package
void *
run_quizzer(void *arg)
{
    struct author *author = (struct author *) arg;
    struct qoutinfo *qo = NULL;
    struct sockinfo si;
    struct epoll_event ev, e[BACK_EVENT] = { 0 };
    int range = 0, i, j, idrowback = 0, ret, torec, epfd;
    uint nowtime, keyval, intime, delid;
    ushort id;
    pthread_detach(pthread_self());
    epfd = add_backdoor(author->audp);
    author->bdepfd = epfd;
    while (1) {
        idrowback = random() % (ID_SPACE / LIST_SPACE);
        launch_new_query(author, idrowback);
        handle_back_event(author);
        if (author->idx == 0)   //main author
        {
            check_ttl_expire(author);
            if (check_mm_cache(author) == 1)
                dup_data_into_db(author);
            else
                author->dupbefore = 0;
            check_refresh_flag(author);
        }
    }
}


//add to quizzer
int
add_to_quizzer(struct qoutinfo *qo, struct server *s, int qidx)
{
    int i, j, randomoff = 0;
    struct qoutinfo *qi = NULL;
    qi = malloc(sizeof(struct qoutinfo));
    if (qi == NULL)
        return -1;
    memset(qi, 0, sizeof(struct qoutinfo));
    *qi = *qo;
    qi->cli = NULL;
    if (qo->cli != NULL) {
        qi->cli = malloc(sizeof(struct sockinfo));
        if (qi->cli == NULL) {
            free(qi);
            return -1;
        }
        memcpy(qi->cli, qo->cli, sizeof(struct sockinfo));
    }
    qi->stat = NEW_QUERY;
    randomoff = random() % LIST_SPACE;
    for (j = qidx; j < QUIZZER_NUM; j++) {
        pthread_mutex_lock(&s->authors[j].lock);
        for (i = randomoff; i < LIST_SPACE; i++) {
            if (s->authors[j].list[i] == NULL) {
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_mutex_unlock(&s->authors[j].lock);
                return 0;
            }
        }
        for (i = 0; i < randomoff; i++) {
            if (s->authors[j].list[i] == NULL) {
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_mutex_unlock(&s->authors[j].lock);
                return 0;
            }
        }
        pthread_mutex_unlock(&s->authors[j].lock);
    }
    for (j = 0; j < qidx; j++) {
        pthread_mutex_lock(&s->authors[j].lock);
        for (i = randomoff; i < LIST_SPACE; i++) {
            if (s->authors[j].list[i] == NULL) {
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_mutex_unlock(&s->authors[j].lock);
                return 0;
            }
        }
        for (i = 0; i < randomoff; i++) {
            if (s->authors[j].list[i] == NULL) {
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_mutex_unlock(&s->authors[j].lock);
                return 0;
            }
        }
        pthread_mutex_unlock(&s->authors[j].lock);
    }
    if (qo->cli != NULL)
        free(qi->cli);
    free(qi);
    return -1;
}


//qi and cli are all in stack
//if we want to add them in list
//alloc memory with ad_t_qzzer
int
lock_and_add_to_quizz(struct baseinfo *qi, struct sockinfo *cli,
                      struct fetcher *f)
{
    struct qoutinfo qo = { 0 };
    uchar kbuffer[270] = { 0 };
    int ret;
    static int a[2] = { 0 };
    make_type_domain(qi->origindomain, strlen(qi->origindomain) + 1,
                     qi->type, kbuffer);
    ret = htable_insert(f->s->qlist, kbuffer, NULL, 0, NULL);   //has same one, qeurying
    if (ret != 0)
        return -1;
    qo.qname = qi->type;
    qo.dlen = qi->dlen;
    if (qi->dlen < 1)
        return -1;
    qo.td = malloc(qi->dlen + 1);
    if (qo.td == NULL)
        return -1;
    qo.td[0] = qi->type;
    memcpy(qo.td + 1, qi->origindomain, qi->dlen);
    qo.qing = qo.td + 1;        //at first
    qo.cli = cli;
    qo.cid = qi->id;
    init_qoutinfo(&qo);
    if (add_to_quizzer(&qo, f->s, f->qidx) < 0) {
        f->qidx = (f->qidx + 1) % QUIZZER_NUM;
        htable_delete(f->s->qlist, kbuffer);
        return -1;
    }
    f->qidx = (f->qidx + 1) % QUIZZER_NUM;
    return 0;
}


//format in databuffer
//type.mvalue.data.type.mvalue.data..
int
find_record_from_mem(uchar * otd, int dlen, struct htable *datasets,
                     uchar * databuffer)
{
    uchar type, td[256] = { 0 };
    struct mvalue *mv = NULL;
    int ret, idx, dataidx = 0, clen, debug = 100;
    memcpy(td, otd, dlen + 2);
    type = td[0];
    td[0] = CNAME;
    dataidx++;                  //add 1 for type. value will be type.mvalue.rrset
    while ((ret =
            find_record_with_ttl(datasets, td, databuffer + dataidx,
                                 AUTH_DATA_LEN - dataidx, NULL)) > 0) {
        databuffer[dataidx - 1] = CNAME;        //prev byte is type
        mv = (struct mvalue *) (databuffer + dataidx);
        clen = strlen(databuffer + dataidx + sizeof(struct mvalue)) + 1;
        make_type_domain(databuffer + dataidx + sizeof(struct mvalue),
                         clen, CNAME, td);
        idx = get_pre_mem_hash(td);
        dataidx += ret;
        if (type == CNAME)      //at first time
            return dataidx;
        dataidx++;              //for type
        if (debug-- == 0)       //error
            return -1;
    }
    td[0] = type;
    ret =
        find_record_with_ttl(datasets, td, databuffer + dataidx,
                             AUTH_DATA_LEN - dataidx, NULL);
    if (ret > 0) {
        databuffer[dataidx - 1] = type;
        dataidx += ret;
        return dataidx;
    }
    return -1;
}


//global cron
//delete and close useless tcp fd
int
global_cron(struct server *s)
{
    int fd = -1;
    struct list_node *nds, *tmp;
    struct list *el = &s->eventlist;
    pthread_mutex_lock(&el->lock);
    nds = el->head;
    el->head = NULL;
    pthread_mutex_unlock(&el->lock);
    while (nds != NULL) {
        fd = *(int *) nds->data;
        if (fd > 0)
            close(fd);
        tmp = nds->next;
        free(nds->data);
        free(nds);
        nds = tmp;
    }
    return 0;
}


int
run_fetcher(struct fetcher *f)
{
    struct msgcache *mc = f->mc;
    struct seninfo se = { 0 };
    struct mvalue *mv = NULL, *mvp = NULL, mx;
    struct sockinfo si, *psi = NULL;
    uchar buf[512] = { 0 };
    uchar td[256] = { 0 }, *val = NULL, *itor = NULL;
    uchar mb[MAX_MSG_SIZE + sizeof(uint16_t)] = { 0 };
    uint16_t mblen = 0;
    hashval_t hash;
    int ret = 0, hhead, len = 0, i;
    struct baseinfo qi;
    int counter = 0;
    while (1) {
        bzero(&qi, sizeof(struct baseinfo));
        pthread_mutex_lock(&mc->lock);
        if (mc->head == mc->tail) {
            pthread_mutex_unlock(&mc->lock);
            usleep(1000);
            continue;
        }
        se = *(struct seninfo *) (mc->data + mc->head); //meta data
        memcpy(buf, mc->data + mc->head + sizeof(struct seninfo), se.len);      //data.
        mc->head = mc->head + sizeof(struct seninfo) + se.len;
        if (mc->head + 512 > mc->size)
            mc->head = 0;
        pthread_mutex_unlock(&mc->lock);
        si.buflen = se.len;     //msg len
        si.buf = buf;
        si.socktype = se.type;
        if (si.socktype == UDP) {
            memcpy(&(si.addr), &(se.addr), sizeof(struct sockaddr_in));
            si.fd = f->s->ludp; //use public udp:53
        } else
            si.fd = se.fd;
        qi = passer_dns_data(&si);
        if (qi.err == 1)        //if our thread made error,start over from head==0.
            continue;
        f->dataidx = 0;
        memcpy(td + 1, qi.origindomain, qi.dlen);
        td[0] = qi.type;
        //dbg_print_td(td);
        ret =
            find_record_from_mem(td, qi.dlen, f->s->datasets,
                                 f->databuffer);
        if (ret > 0) {
            //jump [type]
            counter++;
            if (counter % 100 == 0) {
                printf("%d send %d\n", f->idx, counter);
                counter = 0;
            }
            mv = (struct mvalue *) (f->databuffer + 1);
            //printf("mv sg %d,%u\n",ret,mv->seg);
            if (mv->seg > 0) {
                send_msg_to_client(&si, td, qi.id, f->databuffer);
            } else {
                ret =
                    write_back_to_client(mb, td, qi.id, qi.dlen, &si,
                                         f->databuffer, ret);
                if (ret == 0) {
                    mvp = (struct mvalue *) mb;
                    val =
                        malloc(mvp->len + sizeof(struct mvalue) +
                               mvp->seg * sizeof(uint16_t));
                    if (val != NULL) {
                        memcpy(val, mb, sizeof(struct mvalue));
                        mvp = (struct mvalue *) val;
                        mvp->ttl = mv->ttl;
                        mvp->hits = mv->hits;
                        mvp->num = 0;   //not used
                        itor = val + sizeof(struct mvalue);
                        //copy ttloff and msg
                        memcpy(itor, mb + sizeof(struct mvalue),
                               sizeof(uint16_t) * mvp->seg + mvp->len);
                        hash = get_pre_mem_hash(td);
                        htable_insert(f->s->datasets + hash, td, val, 1, &mx);  //replace
                    }
                }
            }
            write_log(&f->logfd, &f->lastlog, f->idx, td + 1, qi.type,
                      &si.addr);
        } else {
            psi = &si;
            if (si.socktype == TCP)
                psi = NULL;
            lock_and_add_to_quizz(&qi, psi, f);
        }
        if (si.socktype == TCP) //not cached, kill tcp
            delete_close_event(si.fd, f);
    }
    return 0;
}
