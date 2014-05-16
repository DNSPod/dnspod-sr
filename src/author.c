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


#include <unistd.h>
#include "author.h"
#include "net.h"

uchar qlist_val[10] = "qlist val";
int
find_record_from_mem(uchar * otd, int dlen, int type, struct htable *datasets,
                     uchar *tdbuffer, uchar * databuffer, hashval_t *hash);
int
add_to_quizzer(struct qoutinfo *qo, struct server *s, int qidx);

int add_query_info(int log_type, int idx, uint16_t type)
{
    int thread_num = 0;
    if (log_type == TYPE_FETCHER) {
        thread_num = idx;
    } else if (log_type == TYPE_QUIZZER) {
        thread_num = idx + FETCHER_NUM;
    } else {
        return -1;
    }
    int query_type_num = query_type_map[type];
    if (query_type_num < 0) {
        return -1;
    }
    global_out_info->query_info[thread_num].query_num[query_type_num]++;
    return 0;
}

//get random number from a buffer
//it's faster than invoke function random every time
//no lock, author use it's own data
union grifa {
    int val;
    uchar randombuffer[sizeof(int)];
};
int
get_random_int_from_author(struct author *author)
{
    int val = 0;
    union grifa tmp;
    if (author->rndidx + sizeof(int) >= RANDOM_SIZE) {
        //read from /dev/urandom
        get_random_data(author->randombuffer, RANDOM_SIZE);
        author->rndidx = 0;
    }
    memcpy(tmp.randombuffer, author->randombuffer + author->rndidx, sizeof(int));
    val = tmp.val;
    //val = *(int *) (author->randombuffer + author->rndidx);
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
    pthread_spin_lock(&el->lock);
    nd->next = el->head;
    el->head = nd;
    pthread_spin_unlock(&el->lock);
    return 0;
}

/*
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
    uint16_t temp = 0;
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
        temp = htons(mv->len);
        memcpy(msgbuf, &temp, sizeof(uint16_t));
        cli->buflen = mv->len + 2;
        cli->buf = msgbuf;
        tcp_write_info(cli, 0);
    }
    return 0;
}
*/


//databuffer format
//type.mvalue.data.type.mvalue.data...
int
// write_back_to_client(uchar * td, enum rrtype otype, uint8_t level, ushort id, int dlen,
write_back_to_client(mbuf_type *mbuf, uchar * fr, int vlen)
{
    struct setheader sh = { 0 };        //data in dns header
    int main_val = 0, dnslen = 0;
    uchar *msg = mbuf->buf, type;      //if bigger, use TCP
    uchar *from = fr, *to = msg;
    struct mvalue *mv = NULL;
    int jump = 0;
    uint16_t temp = 0;
    struct hlpc hlp[100];       //p domians to compression
    hlp[0].name = mbuf->td;
    hlp[0].off = sizeof(dnsheader);
    hlp[0].level = mbuf->lowerdomain.label_count;
    hlp[0].ref = -1;
    hlp[0].mt = 0;
    hlp[0].len = mbuf->dlen;
    jump = sizeof(dnsheader) + mbuf->dlen + sizeof(qdns);
    to = to + jump;
    while (vlen > 1)            //vlen include type.mvalue.data.
    {
        type = from[0];
        mv = (struct mvalue *)(from + 1);
        to = fill_rrset_in_msg(hlp, from, to, main_val, msg);
        if (to == NULL)
            return -1;
//         *to = 0;
        vlen = vlen - 1 - mv->len - sizeof(struct mvalue);
        sh.an += mv->num;
        if (type == CNAME)      //cname must be 1
            main_val++;             //no all rdata is the cname's
        from = from + mv->len + 1 + sizeof(struct mvalue);      // type.mv.len.
    }
    sh.itor = msg;
    sh.dlen = mbuf->dlen;
    sh.od = mbuf->td;
    sh.id = mbuf->id;
    sh.type = mbuf->qtype;
    fill_header_in_msg(&sh);
    dnslen = to - msg;
    mbuf->buflen = dnslen;
    mbuf->addr = &(mbuf->caddr);
    if (mbuf->socktype == UDP) {
        if (dnslen > MAX_UDP_SIZE)
            send_tc_to_client(mbuf);
        else
            udp_write_info(mbuf, 0);     //ignore send error
    } else {
        temp = DNS_GET16(dnslen);
        memcpy(msg - 2, &temp, sizeof(uint16_t));
        mbuf->buflen = dnslen + 2;
        mbuf->buf = msg - 2;
        tcp_write_info(mbuf, 0);
    }
    ////////////////////////////////////////////////////////////
    //key, val, vallen, ttl offset
    //if now + TTL_UPDATE > ttl
    //return
    /* ret = transfer_record_to_msg(msgto, td, msg + 2, dnslen, ttloff); */
    /* if (ret < 0) */
        /* return -1; */
    return 0;
}


//process a segment of data
int
passer_related_data(struct sockinfo *si, mbuf_type *mbuf,
                    struct author *author)
{
    uchar *buf = si->buf, *tail = NULL;
    int stype = 0/*, ret*//*, seg*/;
    struct rbtree *rbt;
    int datalen = 0;
    ushort n;
    struct hlpp hlp;
    dnsheader *hdr = (dnsheader *) buf;
    
    tail = buf + sizeof(dnsheader) + si->lowerdomain->label_len[0];       //domain len
    /* type = ntohs(*(ushort *) tail); */
    /* class = ntohs(*(ushort *) (tail + 2)); */
    tail = tail + 4;
    datalen = si->buflen;
    rbt = author->s->ttlexp;
    n = ntohs(hdr->ancount);
    hlp.stype = &stype;
    hlp.ds = author->s->datasets;
    hlp.rbt = rbt;
    hlp.buf = buf;
    hlp.datalen = datalen;
    hlp.tmpbuf = mbuf->tempbuffer;
    hlp.domainbuf = mbuf->tdbuffer;
    hlp.dmbuf = mbuf->dmbuffer;
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
    ushort id, typeoff, temp, type;
    uchar *buffer = author->tmpbuffer;
    int len, ret;
    mbuf_type *mbuf;
    uchar *domain;
    
    ret = author->eptcpfds[fd].ret;
    if (ret <= 0)
        return -1;
    domain = author->eptcpfds[fd].domain;
    id = GET_IDX(ret);
    typeoff = GET_TYPE(ret);
    htable_find_list(author->s->qlist, domain, typeoff, id, (uchar **)&mbuf);
    type = mbuf->qtype;
    if (mbuf->qname == Q_NS)
        type = A;
    len = make_dns_msg_for_new(buffer + 2, mbuf->aid, mbuf->qing, mbuf->qlen, type);
    temp = htons(len);
    memcpy(buffer, &temp, sizeof(ushort));
    mbuf->fd = fd;
    mbuf->buf = buffer;
    mbuf->buflen = len + 2;
    tcp_write_info(mbuf, 0);
    return 0;
}


//connect to server, tcp is expensive, we use 1 addr once
//do connect thing
//send thing will be done in cb_read_callback xxxx
int
query_from_auth_tcp(struct author *author, mbuf_type *mbuf)
{
    struct sockinfo si;
    int i, st = 0;
    uchar *ip = author->ip;
    struct mvalue *mv = NULL;
    mv = (struct mvalue *) ip;
    while (mv->num > 0) {
        ip += sizeof(struct mvalue);
        for (i = 0; i < mv->num; i++) {
            if (st == (mbuf->tcpnums - 1)) {
                si.fd = mbuf->tcpfd;
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
query_from_auth_server(mbuf_type *mbuf, struct author *author)
{
    ushort id = mbuf->aid, type;
    uchar *buffer = mbuf->tempbuffer;
    uchar *ip = author->ip;
    int len, i, st = 1, ret;
    struct mvalue *mv = NULL;
//     struct sockinfo si;
    
    //dbg_print_td(qo->td);
    if (mbuf->qname == Q_NS)
        type = A;
    else
        type = mbuf->qtype;
    mbuf->mxtry++;
    if (mbuf->socktype == UDP) {
        len = make_dns_msg_for_new(buffer, id, mbuf->qing, mbuf->qlen, type);
        mbuf->buf = buffer;
        mbuf->buflen = len;
        mbuf->fd = author->audp;
        mv = (struct mvalue *) ip;
        while (mv->num > 0) {
            ip += sizeof(struct mvalue);
            for (i = 0; i < mv->num; i++) {
                make_addr_from_bin(&(mbuf->aaddr), ip + i * 4);     //ipv4 only
                //dbg_print_addr((struct sockaddr_in*)&(si.addr));
                mbuf->aaddr.sin_port = htons(53);
                mbuf->addr = &(mbuf->aaddr);
                ret = udp_write_info(mbuf, 0);
                if (ret > 0)    //success
                    st++;
                if (st > mbuf->mxtry)
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


//clear the querying bit, free struct
//clear the querying bit, free struct
int
release_qoutinfo(struct author *author, mbuf_type *mbuf, uint32_t idx)
{
    int fd = mbuf->tcpfd, epfd;
    int id, typeoff;
    uchar *val;
    
    if (fd > 0)
    {
        struct epoll_event ev = {0};
        epfd = author->bdepfd;
        author->tcpinuse--;
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
        author->eptcpfds[fd].ret = 0;
        close(fd);
    }
    id = GET_IDX(idx);
    typeoff = GET_TYPE(idx);
    val = htable_delete_list(author->s->qlist, mbuf->lowerdomain.domain, typeoff, id);
    assert(val == (void *)mbuf);
    mbuf_free(mbuf);
    
    return 0;
}

int
init_qoutinfo(mbuf_type *mbuf)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    mbuf->socktype = UDP;
    mbuf->mxtry = 0;
    mbuf->qns = 1;                //default query ns.
    mbuf->sq = 1;                 //default send query
    mbuf->stime = tv.tv_sec * 1000 + tv.tv_usec / 1000;;
    mbuf->tcpfd = 0;
    mbuf->qtimes = 0;
    mbuf->tdbuffer = NULL;
    mbuf->tempbuffer = NULL;
    mbuf->dmbuffer = NULL;
    mbuf->ipbuffer = NULL;
    mbuf->hascname = 0;
    mbuf->tcpnums = 0;
    mbuf->stat = NEW_QUERY;

    return 0;
}


//-1 error
//-2 tc
//0 continue
//1 normal
int
check_enter(struct author *author, uchar * buf, int *idx, mbuf_type **mbuf, packet_type *lowerdomain)
{
    int32_t id, typeoff;
    int /*off, */ret;
    int tx = 0;
    dnsheader *hdr = (dnsheader *) buf;
    *idx = hdr->id;
    id = GET_IDX(hdr->id);
    typeoff = GET_TYPE(hdr->id);
    if (id >= QLIST_TABLE_SIZE || typeoff >= SUPPORT_TYPE_NUM)
        return -1;
    ret = check_dns_name(buf + sizeof(dnsheader), lowerdomain);
    if (ret < 0)
        return -1;
    ret = htable_find_list(author->s->qlist, lowerdomain->domain, typeoff, id, (uchar **)mbuf);
    if (ret < 0)
        return -1;
    
    if ((*mbuf)->stat == NEW_QUERY)
    {
        *mbuf = NULL;
        return -1;
    }
    
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
    (*mbuf)->socktype = UDP;         //default
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
    int idx, ret, pret;
    mbuf_type *mbuf = NULL;
    ushort xtype = 0;
    dnsheader *hdr = (dnsheader *) buf;
    packet_type lowerdomain;
    //msg buffer
    ret = check_enter(author, buf, &idx, &mbuf, &lowerdomain);
    mbuf_free(si->mbuf);
    si->mbuf = mbuf;
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
    mbuf->mxtry--;
    if (ret == -3)              //format error, server refused, error...
    {
        mbuf->qtimes++;
        return 0;
    }
    si->lowerdomain = &lowerdomain;
    pret = passer_related_data(si, mbuf, author);
    if (pret < 0)
        return 0;               //error msg,continue
    mbuf->fd = author->s->ludp;
    mbuf->addr = &(mbuf->caddr);
    if (pret == CNAME && mbuf->qtype == CNAME) {
        if (mbuf->fd != -1) {
            *(ushort *) buf = mbuf->cid;
            mbuf->buf = buf;
            mbuf->buflen = si->buflen;
            
            if (si->buflen > MAX_UDP_SIZE)
                send_tc_to_client(mbuf);
            else {
                udp_write_info(mbuf, 0);     //cname..
                write_log(author->loginfo, author->idx,
                          mbuf->td, mbuf->dlen, mbuf->qtype, mbuf->addr);
            }
        }
        return idx + 1;
    }
    if (pret == CNAME || mbuf->qname != Q_DOMAIN) {
        mbuf->stat = PROCESS_QUERY;
        mbuf->socktype = UDP;     //if prev we use tcp, use udp again
        return 0;
    }
    if ((pret == SOA) || (ntohs(hdr->ancount) > 0)) {
        if (mbuf->fd != -1) {
            if (mbuf->hascname == 0) {
                *(ushort *) buf = mbuf->cid;      //no need to htons
                mbuf->buf = buf;
                mbuf->buflen = si->buflen;
                if (si->buflen > MAX_UDP_SIZE)
                    send_tc_to_client(mbuf);
                else {
                    udp_write_info(mbuf, 0);
                    write_log(author->loginfo,
                              author->idx, mbuf->td, mbuf->dlen, mbuf->qtype,
                              mbuf->addr);
                }
            } else              //has a cname,put the origin domain first
            {
                if (pret == SOA) {
                        xtype = CNAME;
                }
                else
                    xtype = mbuf->qtype;
                ret =
                    find_record_from_mem(mbuf->td, mbuf->dlen, xtype, 
                                         author->s->datasets,
                                         author->tmpbuffer,
                                         author->databuffer,
                                         &(mbuf->lowerdomain.hash[0]));
                if (ret > 0) {
                    author->response++;
                    if (mbuf->fd != -1) {
                        mbuf->buf = mbuf->data + 2;
                        write_back_to_client(mbuf, author->databuffer, ret);
                    }
                    write_log(author->loginfo, author->idx, mbuf->td, mbuf->dlen, mbuf->qtype, mbuf->addr);
                }
            }
        }
        //else printf("update record\n");
        return idx + 1;
    }
    mbuf->stat = PROCESS_QUERY;   //no need to find_addr in launch_new_qu
    mbuf->socktype = UDP;
    return 0;
}


//read from auth server
int
cb_read_auth(struct epoll_event *ev, struct sockinfo *si)
{
    int ret, szhdr = sizeof(dnsheader);
    mbuf_type *mbuf = mbuf_alloc();
    if (NULL == mbuf)
        return -1;
    mbuf->fd = ev->data.fd;
    mbuf->buf = si->buf;
    mbuf->buflen = BIG_MEM_STEP;
    mbuf->addr = &(mbuf->aaddr);
    if (si->socktype == TCP)
        ret = tcp_read_dns_msg(mbuf, MBUF_DATA_LEN - 2, 0);
    else
        ret = udp_read_msg(mbuf, 0);      //epoll return and no blocked here
    if (ret < szhdr)
    {
        mbuf_free(mbuf);
        return -1;
    }
    si->buflen = mbuf->buflen = ret;
    si->mbuf = mbuf;
    return ret;
}

int
launch_new_query(struct author *author/*, int idrowback*/)
{
    int new_query = 0, i, start, end, ret;
    mbuf_type *mbuf;
    struct timeval tv;
    uint64_t msnow = 0;
    int slotoff, typeoff;
    start = author->start;
    end = author->end;
    gettimeofday(&tv, NULL);
    msnow = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    for (i = start; i < end; i++) {
        slotoff = 0;
        typeoff = 0;
        ret = htable_find_list_io(author->s->qlist, i, slotoff, &typeoff, (uchar **)&mbuf);
        while (ret >= 0)
        {
            if (ret > 0)
            {
                if (mbuf->qtimes > MAX_TRY_TIMES || (msnow - mbuf->stime) > 5000)
                {
                    release_qoutinfo(author, mbuf, GET_AID(i, typeoff));
                }
                else
                {
                    if (mbuf->stat == NEW_QUERY)
                    {
                        assert(i < QLIST_TABLE_SIZE && typeoff < SUPPORT_TYPE_NUM);
                        mbuf->aid = GET_AID(i, typeoff);   //start id
                        mbuf->backid = mbuf->aid;
                        mbuf->mxtry = 0;
                        if (mbuf->fd != -1)
                            mbuf->fd = author->cudp;
                        mbuf->tdbuffer = author->tdbuffer;
                        mbuf->tempbuffer = author->tempbuffer;
                        mbuf->dmbuffer = author->dmbuffer;
                        mbuf->ipbuffer = author->ipbuffer;
                        new_query++;
                        mbuf->stat = PROCESS_QUERY;
                    }
                    if ((msnow - mbuf->stime) > 1000 && (mbuf->sq == 0))
                    {
                        mbuf->sq = 1;
                    }
                    if ((mbuf->socktype == UDP) && (mbuf->sq == 1)) {
                        ret =
                            find_addr(author->s->forward, author->s->datasets, mbuf,
                                    author->ip, author->s->is_forward);
                        if (mbuf->stat == PROCESS_QUERY && ret == 0)
                            query_from_auth_server(mbuf, author);
                        mbuf->qtimes++;
//                         mbuf->stime = msnow;
                    }
                }
                
            }
            if (ret == 0 || (typeoff == (SUPPORT_TYPE_NUM- 1)))
            {
                slotoff++;
                typeoff = 0;
            }
            else
                typeoff++;
            
            mbuf = NULL;
            ret = htable_find_list_io(author->s->qlist, i, slotoff, &typeoff, (uchar **)&mbuf);
        }
    }

    return new_query;
}


int
after_pass_data(int ret, struct author *author, mbuf_type *mbuf)
{
    struct epoll_event ev = {0};
    int fd;
    if (ret == 0)
        return 0;
    if (mbuf == NULL)
        return -1;
    if (ret < 0)                //tcp needed.
    {
        //printf("tcp needed\n");
        ret = ret + 1;
        ret = -ret;
        
        if ((mbuf->tcpfd > 0) && ((mbuf->qtimes % (MAX_TRY_TIMES / 3)) == 0))       //retry tcp
        {
            ev.data.fd = mbuf->tcpfd;
            mbuf->tcpfd = 0;
            author->tcpinuse--;
            epoll_ctl(author->bdepfd, EPOLL_CTL_DEL, ev.data.fd, &ev);
            close(ev.data.fd);
        }
        if (mbuf->tcpfd > 0)      //processing...
            return 0;
        //restart..
        if (author->tcpinuse > (LIST_SPACE / 10))
            fd = -1;            //too many tcps
        else {
            mbuf->tcpnums++;
            fd = socket(AF_INET, SOCK_STREAM, 0);
        }
        if (fd > 0) {
            author->tcpinuse++;
            mbuf->tcpfd = fd;
            mbuf->socktype = TCP;
            ev.data.fd = fd;
            ev.events = EPOLLOUT;       //wait for ready to write
            author->eptcpfds[fd].ret = ret;
            memcpy(author->eptcpfds[fd].domain, mbuf->td, mbuf->dlen);
            set_non_block(fd);
            set_recv_timeout(fd, 0, 500);       //half second
            epoll_ctl(author->bdepfd, EPOLL_CTL_ADD, fd, &ev);
            query_from_auth_tcp(author, mbuf);
            return 0;
        } else
            ret++;              //fix ret value, for deleting afterword
    }

    if (ret > 0)                //delete qoutinfo
    {
        ret = ret - 1;          //minus the 1 p_a_d added
        release_qoutinfo(author, mbuf, ret);
    }
    return 0;
}



int
handle_back_event(struct author *author)
{
    int infinite = 1, ret, i, epfd = author->bdepfd;
    struct sockinfo si = {{0}};
    int bf = 0, rx;
    struct epoll_event ev = {0}, *e = author->e;
    uchar *buf = author->tmpbuffer;
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
                    after_pass_data(rx, author, si.mbuf);
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
                        author->eptcpfds[e[i].data.fd].ret = 0;
                        close(e[i].data.fd);
                        ev.data.fd = e[i].data.fd;
                        mbuf_free(si.mbuf);
                        epoll_ctl(epfd, EPOLL_CTL_DEL, ev.data.fd, &ev);
                    } else {
                        rx = passer_auth_data(author, buf, &si);
                        after_pass_data(rx, author, si.mbuf);
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
                    author->eptcpfds[e[i].data.fd].ret = 0;
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
    uint i, limit;
    struct rbtree *rbt = a->s->ttlexp;
    uint dboff, dbidx/*, slotoff*/;

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
        htable_find_io(a->s->datasets + dboff, dbidx,/* slotoff, buffer,
                        key, &dlen, 1999, */limit, rbt, TTL_UPDATE);
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
        pthread_spin_lock(&author->s->datasets[i].lock);
        total += author->s->datasets[i].now;
        pthread_spin_unlock(&author->s->datasets[i].lock);
    }
    tmx++;
    if (total > MAX_ELE_NUM)
        return 1;
    return 0;
}


int
check_ttl_expire(struct author *author)
{
    time_t now;
    struct ttlnode *tn = NULL;
    struct rbnode *pn = NULL;
    mbuf_type *mbuf;
    int ret = -1;
    struct rbtree *rbt = NULL;
    
    mbuf = mbuf_alloc();
    if (NULL == mbuf)
        return -1;
    now = global_now;
    /* ds = author->s->datasets; */
    rbt = author->s->ttlexp;
    pthread_spin_lock(&rbt->lock);
    pn = min_node(rbt);
    while (pn != NULL) {
        tn = pn->key;
        //if exp was 12, now was 11, start
        //if exp was 12, now was 5, break
        if (tn->exp > (now + TTL_UPDATE))       //3 secs after it will not expire
            break;
        /* printf("ttl refresh "); */
        /* dbg_print_td(tn->data); */
        tn = delete_node(rbt, pn);
        pthread_spin_unlock(&rbt->lock);
        if (tn != NULL) {
            mbuf->qname = tn->type;     //type
            mbuf->qtype = tn->type;
            mbuf->dlen = tn->dlen;
            memcpy(&(mbuf->lowerdomain), tn->lowerdomain, sizeof(packet_type));
            int i;
            for (i = 0; i < tn->lowerdomain->label_count; i++)
            {
                mbuf->lowerdomain.label[i] = mbuf->lowerdomain.domain + mbuf->lowerdomain.label_offsets[i];
            }
            mbuf->qhash = &(mbuf->lowerdomain.hash[0]);
            mbuf->td = mbuf->lowerdomain.domain;
            mbuf->qing = mbuf->td;
            mbuf->qlen = mbuf->dlen;
            mbuf->cid = 0;
            mbuf->fd = -1;
            init_qoutinfo(mbuf);
            ret = htable_insert_list(author->s->qlist, tn->data, tn->dlen, tn->type, (uchar *)mbuf, 0, NULL, tn->hash); //not replace
            if (0 == ret)
            {
                mbuf = mbuf_alloc();
                if (NULL == mbuf)
                {
                    free(tn->lowerdomain);
                    free(tn);
                    return -1;
                }
            }
            //else querying lost
            free(tn->lowerdomain);
            free(tn);
        }
        pthread_spin_lock(&rbt->lock);
        pn = min_node(rbt);
    }
    mbuf_free(mbuf);
    pthread_spin_unlock(&rbt->lock);
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
    int /*idrowback = 0,*/ epfd;
    pthread_detach(pthread_self());
    epfd = add_backdoor(author->audp);
    author->bdepfd = epfd;
    while (1) {
        launch_new_query(author);
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
    struct qoutinfo *qi = qo;

    qi->stat = NEW_QUERY;
    randomoff = random() % LIST_SPACE;
    for (j = qidx; j < QUIZZER_NUM; j++) {
//         pthread_mutex_lock(&s->authors[j].lock);
        for (i = randomoff; i < LIST_SPACE; i++) {
            if (s->authors[j].list[i] == NULL) {
                pthread_spin_lock(&s->authors[j].lock);
                if (s->authors[j].list[i] != NULL)
                {
                    pthread_spin_unlock(&s->authors[j].lock);
                    continue;
                }
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_spin_unlock(&s->authors[j].lock);
                return 0;
            }
        }
        for (i = 0; i < randomoff; i++) {
            if (s->authors[j].list[i] == NULL) {
                pthread_spin_lock(&s->authors[j].lock);
                if (s->authors[j].list[i] != NULL)
                {
                    pthread_spin_unlock(&s->authors[j].lock);
                    continue;
                }
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_spin_unlock(&s->authors[j].lock);
                return 0;
            }
        }
//         pthread_mutex_unlock(&s->authors[j].lock);
    }
    for (j = 0; j < qidx; j++) {
//         pthread_mutex_lock(&s->authors[j].lock);
        for (i = randomoff; i < LIST_SPACE; i++) {
            if (s->authors[j].list[i] == NULL) {
                pthread_spin_lock(&s->authors[j].lock);
                if (s->authors[j].list[i] != NULL)
                {
                    pthread_spin_unlock(&s->authors[j].lock);
                    continue;
                }
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_spin_unlock(&s->authors[j].lock);
                return 0;
            }
        }
        for (i = 0; i < randomoff; i++) {
            if (s->authors[j].list[i] == NULL) {
                pthread_spin_lock(&s->authors[j].lock);
                if (s->authors[j].list[i] != NULL)
                {
                    pthread_spin_unlock(&s->authors[j].lock);
                    continue;
                }
                s->authors[j].list[i] = qi;
                s->authors[j].qnum++;
                pthread_spin_unlock(&s->authors[j].lock);
                return 0;
            }
        }
//         pthread_mutex_unlock(&s->authors[j].lock);
    }
    
    return -1;
}


//qi and cli are all in stack
//if we want to add them in list
//alloc memory with ad_t_qzzer
int
lock_and_add_to_quizz(mbuf_type *mbuf, struct fetcher *f)
{
    int ret;
    
    if (mbuf->dlen < 1)
        return -1;
    
    mbuf->qname = mbuf->qtype;
    mbuf->td = mbuf->lowerdomain.domain;
    mbuf->qing = mbuf->td;        //at first
    mbuf->qhash = &(mbuf->lowerdomain.hash[0]);
    mbuf->qlen = mbuf->dlen;
    mbuf->cid = mbuf->id;
    init_qoutinfo(mbuf);

    ret = htable_insert_list(f->s->qlist, mbuf->lowerdomain.domain, mbuf->dlen, mbuf->qtype, (uchar *)mbuf, 0, NULL, &(mbuf->lowerdomain.hash[0]));   //has same one, qeurying
    if (ret != 0)
    {
        return -1;
    }
    
    return 0;
}


//format in databuffer
//type.mvalue.data.type.mvalue.data..
int
find_record_from_mem(uchar * otd, int dlen, int type, struct htable *datasets,
                     uchar * tdbuffer, uchar * databuffer, hashval_t *hash)
{
    uchar /*type, */*td = otd;
    int ret, dataidx = 0, clen, debug = 100;
    hashval_t thash, *h = hash;
    dataidx++;                  //add 1 for type. value will be type.mvalue.rrset
    if (type != CNAME)
    {
        while ((ret =
                find_record_with_ttl(datasets, td, dlen, CNAME, databuffer + dataidx,
                                    AUTH_DATA_LEN - dataidx, NULL, h)) > 0) {
            databuffer[dataidx - 1] = CNAME;        //prev byte is type
            clen = ret - sizeof(struct mvalue);
            td = tdbuffer;
            memcpy(td, databuffer + dataidx + sizeof(struct mvalue), clen);
            dataidx += ret;
            dataidx++;              //for type
            if (debug-- == 0)       //error
                return -1;
            thash = 0;
            h = &thash;
            dlen = clen;
        }
        thash = 0;
    }
    ret =
        find_record_with_ttl(datasets, td, dlen, type, databuffer + dataidx,
                             AUTH_DATA_LEN - dataidx, NULL, h);
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
    pthread_spin_lock(&el->lock);
    nds = el->head;
    el->head = NULL;
    pthread_spin_unlock(&el->lock);
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
    int ret = 0;
    mbuf_type *mbuf;
    int fd;
    
    while (1) {
        fd = -1;
        pthread_spin_lock(&mc->lock);
        if (mc->pkt == 0) {
            pthread_spin_unlock(&mc->lock);
            usleep(1000);
            continue;
        }
        memcpy(&mbuf, mc->data + mc->head, sizeof(void *));
        mc->head = mc->head + sizeof(void *);//sizeof(struct seninfo) + se->len;
        if (mc->head + 8 > mc->size)
            mc->head = 0;
        mc->pkt--;
        pthread_spin_unlock(&mc->lock);
        if (mbuf->socktype == UDP) {
            mbuf->fd = f->s->ludp; //use public udp:53
        } 
        passer_dns_data(mbuf);
        if (mbuf->err == 1)        //if our thread made error,start over from head==0.
        {
            mbuf_free(mbuf);
            continue;
        }
        f->dataidx = 0;
        mbuf->td = mbuf->lowerdomain.domain;
        //dbg_print_td(td);
        ret =
            find_record_from_mem(mbuf->td, mbuf->dlen, mbuf->qtype, f->s->datasets,
                        f->tdbuffer, f->databuffer, &(mbuf->lowerdomain.hash[0]));
        if (ret > 0) {
            write_back_to_client(mbuf, f->databuffer, ret);
            write_log(f->loginfo, f->idx, mbuf->td, mbuf->dlen - 1, mbuf->qtype,
                     mbuf->addr);
            mbuf_free(mbuf);
        } else {
            if (mbuf->socktype == TCP)
            {
                fd = mbuf->fd;
                mbuf->fd = -1;
            }
            if (lock_and_add_to_quizz(mbuf, f) < 0)
            {
                f->miss++;
                mbuf_free(mbuf);
            }
        }
        if (fd != -1) //not cached, kill tcp
            delete_close_event(fd, f);
    }
    return 0;
}
