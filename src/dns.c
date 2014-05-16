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


#include "dns.h"

extern char *g_nameservers[];

// //types we support at the moment
const enum rrtype support_type[SUPPORT_TYPE_NUM] =
    { A, NS, CNAME, SOA, MX, TXT, AAAA, SRV, PTR };


////////////////////////////////////////////////////////////////////
//'a','.','b','.','c','.',0
// 1 ,'a','1','b', 1, 'c',0
uchar *
str_to_len_label(uchar * domain, int len)
{
    uchar l = 0;
    int i;
    //we need a extran byte to put len.
    if (domain[len - 1] != 0 || domain[len - 2] != '.')
        return NULL;
    for (i = len - 2; i > 0; i--) {
        domain[i] = domain[i - 1];
        l++;
        if (domain[i] == '.') {
            domain[i] = l - 1;
            l = 0;
        }
    }
    domain[0] = l;
    return domain;
}


//we do not support type DS, KEY etc.
int
check_support_type(ushort type)
{
    int i, num = SUPPORT_TYPE_NUM;
    for (i = 0; i < num; i++)
        if (type == support_type[i])
            return 0;
    return -1;
}


//make import info into struct baseinfo
void
passer_dns_data(mbuf_type *mbuf)
{
    uchar *buf = mbuf->buf;
    int num;
    int dlen = 0;
    uchar *tail = NULL;
    dnsheader *hdr = (dnsheader *) buf;
    mbuf->err = 1;
    num = ntohs(hdr->qdcount);
    if (num != 1)
        return;
    num = ntohs(hdr->ancount);
    if (num != 0)
        return;
    num = ntohs(hdr->nscount);
    if (num != 0)
        return ;
    num = ntohs(hdr->arcount);
    if (num > 1)                //edns makes ar==1
        return;
    mbuf->id = hdr->id;
    dlen = check_dns_name(buf + sizeof(dnsheader), &(mbuf->lowerdomain));
    if (dlen < 0)
    {
        return;
    }
    mbuf->dlen = dlen;
    tail = mbuf->origindomain = buf + sizeof(dnsheader);
    tail += dlen;
    mbuf->qtype = ntohs(*(ushort *) tail);
    if (check_support_type(mbuf->qtype) == 0)
        mbuf->err = 0;
    return;
}


//we'd better send the right domain and id
int
send_tc_to_client(mbuf_type *mbuf)
{
    uchar *itor = mbuf->buf;
    dnsheader *hdr = (dnsheader *) itor;
    qdns *qd = NULL;
    if (mbuf->td == NULL)
        return -1;
    hdr->id = mbuf->id;
    hdr->flags = 0;
    hdr->flags = SET_QR_R(hdr->flags);
    hdr->flags = SET_RA(hdr->flags);
    hdr->flags = SET_TC(hdr->flags);
    hdr->flags = htons(hdr->flags);
    hdr->qdcount = htons(1);
    hdr->ancount = hdr->nscount = hdr->arcount = htons(0);
    itor += sizeof(dnsheader);
    memcpy(itor, mbuf->td, mbuf->dlen);
    itor = itor + mbuf->dlen;
    qd = (qdns *) itor;
    qd->type = htons(mbuf->qtype);
    qd->dclass = htons(CLASS_IN);
    itor += sizeof(qdns);
    mbuf->buflen = itor - mbuf->buf;
    udp_write_info(mbuf, 0);
    return 0;
}


//transfrom domain from lenlabel format to string
int
get_domain_from_msg(uchar * itor, uchar * hdr, uchar * to, int *tmplen)
{
    uchar len;
    ushort offset = 0;
    len = itor[0];
    int dlen = 0;
    int hasptr = 0, infinite = 20;
    offset = htons((ushort) * (ushort *) itor);
    *tmplen = 0;
    while ((len != 0) && (infinite--)) {
        if (IS_PTR(offset)) {
            itor = hdr + GET_OFFSET(offset);
            if (hasptr == 0) {
                dlen = 2;
                if (*tmplen != 0)
                    dlen += *tmplen;
            }
            hasptr = 1;
        }
        to[0] = itor[0];
        *tmplen += 1;            //len
        *tmplen += to[0];        //label
        if (to[0] > 64)
            return -1;
        to++;
        memcpy(to, itor + 1, itor[0]);
        to += itor[0];
        itor = itor + itor[0] + 1;
        len = itor[0];
        offset = htons((ushort) * (ushort *) itor);
    }
    if (infinite <= 0)          //loops error
        return -1;
    to[0] = 0;
    to++;
    (*tmplen)++;
    if (dlen == 0)
        dlen = *tmplen;          //root len is 1
    if (dlen > MAX_DOMAIN_LEN)
        return -1;
    return dlen;
}


//malloced here
//tn will be free by author before add_to_quizzer
//and lowerdomain will be free by release_qoutinfo
int
insert_into_ttltree(struct rbtree *rbt, uchar * td, int len, int type, uint ttl, packet_type *lowerdomain)
{
    /* printf("insert into ttltree, ttl: %d ", ttl); */
    /* dbg_print_td(td); */
    struct rbnode node = { 0 };
    struct ttlnode *tn = NULL;
    if ((tn = malloc(sizeof(struct ttlnode))) == NULL)
        return -1;
    if ((tn->lowerdomain = malloc(sizeof(packet_type))) == NULL) {
        free(tn);
        return -1;
    }
    tn->dlen = len;
    tn->exp = ttl;
    tn->type = type;
    tn->hash = &(tn->lowerdomain->hash[0]);
    memcpy(tn->lowerdomain, lowerdomain, sizeof(packet_type));
    int i;
    for (i = 0; i < tn->lowerdomain->label_count; i++)
    {
        tn->lowerdomain->label[i] = tn->lowerdomain->domain + tn->lowerdomain->label_offsets[i];
    }
    tn->data = tn->lowerdomain->domain;
    node.key = tn;
    insert_node(rbt, &node);
    return 0;
}


uint
random_ttl(uint ttl)
{
    uint ret = ttl % 7;
    ttl = ttl + ret * 3;
    if (ttl > MAX_TTL)
        ttl = MAX_TTL - (ttl % MAX_TTL);
    return ttl;
}


int
is_parent(uchar * parent, uchar * son)
{
    int sp, ss, x;
    sp = strlen((const char *)parent);
    ss = strlen((const char *)son);
    if (ss < sp)
        return -1;
    x = ss - sp;
    son = son + x;
    if (strcmp((const char *)parent, (const char *)son) == 0)
        return 0;
    return -1;
}


//if we query abc.com
//the auth server returned
//bbc.com NS ns1.sina.com
//we should reject this
int
check_dms(uchar * ck, uchar * dms, int num)
{
    return 0;
}


//when we insert "ttl expired" in the rbtree
//if A or CNAME or MX or TXT or ... 's ttl is small, then we don't need to insert
//NS's "ttl expired" element, we update the record at the same time when we
//update A or CNAME Or MX or TXT or....
//if NS's ttl is small than A or CNAME or MX or TXT or ...
//we update it when update A or CNAME or MX or TXT, or when some query some domain's NS
//in brief, we insert ANSWER section into ttl tree only.
uchar *
process_rdata(struct hlpp * hlp, uchar * label, int n)
{
    uchar *buffer = hlp->tmpbuf;
    ushort type = 0, classin, lth, tmptype = 0;
    uint ttl = 0, tmpttl = 0, tx;
    int i, dlen, ret, tmplen = 0;
    int *stype = hlp->stype;
    struct htable *ds = hlp->ds;
    struct rbtree *rbt = hlp->rbt;
    uchar *hdr = hlp->buf;
    int mlen = hlp->datalen;
    struct mvalue *mv = (struct mvalue *) buffer;
    uchar *tmpdomain = hlp->domainbuf, *dm, *itor = NULL;
    packet_type lowerdomain;
    dm = lowerdomain.domain;
    
    memset(mv, 0, sizeof(struct mvalue));
    itor = buffer + sizeof(struct mvalue);
    tx = global_now;            ///
    dm[0] = dm[1] = 0;
    //if(hlp->section != AN_SECTION) //see header comments.
    rbt = NULL; 
    for (i = 0; i < n; i++) {
        dlen = get_domain_from_msg(label, hdr, tmpdomain, &tmplen);
        if (dm[0] == 0 && dm[1] == 0)   //first time
        {
            check_dns_name(tmpdomain, &lowerdomain);
        }
        if (dlen < 0)
            return NULL;
        label += dlen;
        if (get_dns_info(label, &tmptype, &classin, &ttl, &lth) < 0)
            return NULL;
        if (ttl < MIN_TTL)
            ttl = MIN_TTL;
        ttl = random_ttl(ttl + n);
        label += 10;            // 2type,2class,4ttl,2lth
        if (tmptype == SOA || tmptype == CNAME)
            *stype = tmptype;
        if (type == 0)          //first time
            type = tmptype;
        if (ttl > MAX_TTL)
            ttl = MAX_TTL;
        if (tmpttl == 0)        //first time
            tmpttl = ttl;
        if ((dict_comp_str_equ(tmpdomain, dm) != 0) || (type != tmptype)) {
            mv->ttl = random_ttl(tmpttl + i + (tx % 5)) + tx;
            //23com0
            if (dm[dm[0] + 2] != 0)     //not top level domain
                insert_kv_mem(rbt, ds, dm, lowerdomain.label_len[0], type, buffer,
                              mv->len + sizeof(struct mvalue), 0, &lowerdomain);
            type = tmptype;
            check_dns_name(tmpdomain, &lowerdomain);
            memset(mv, 0, sizeof(struct mvalue));
            itor = buffer + sizeof(struct mvalue);
        }
        ret = fill_rrset_in_buffer(itor, label, hdr, lth, type, hlp);
        if (ret > 0) {
            itor += ret;        //in dns msg
            mv->len += ret;     //in memory
            mv->num++;
        }
        tmpttl = ttl;
        label += lth;
        if ((label < hdr) || (label > (hdr + mlen)))
            return NULL;
    }
    if (mv->num > 0) {
        mv->ttl = random_ttl(tmpttl + i + (tx % 5)) + tx;
        mv->hits = 0;
        mv->seg = 0;
        if (dm[dm[0] + 2] != 0) //not top level domain
            insert_kv_mem(rbt, ds, dm, lowerdomain.label_len[0], type, buffer,
                          mv->len + sizeof(struct mvalue), 0, &lowerdomain);
    }
    return label;
}


int
check_domain_mask(uchar * domain, uchar * origin, int len)
{
    return strncmp((const char *)origin, (const char *)domain, len);
}


int
get_dns_info(uchar * label, ushort * tp, ushort * cls, uint * ttl,
             ushort * lth)
{
    ushort *us = NULL;
    uint *ui = NULL;
    us = (ushort *) label;
    *tp = ntohs(*us);           //type
    if (*tp > 254) {
        printf("type is %u\n", *tp);
        return -1;
    }
    label += sizeof(ushort);
    us = (ushort *) label;
    *cls = ntohs(*us);
    if (*cls != CLASS_IN)
        return -1;
    label += sizeof(ushort);
    ui = (uint *) label;
    *ttl = ntohl(*ui);
    label += sizeof(uint);
    us = (ushort *) label;
    *lth = ntohs(*us);
    return 0;
}


//check dns name and to lower table
unsigned char DnsNameTable[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0X2D,0,0,
    0X30,0X31,0X32,0X33,0X34,0X35,0X36,0X37,0X38,0X39,0,0,0,0,0,0,
    0,0X61,0X62,0X63,0X64,0X65,0X66,0X67,0X68,0X69,0X6A,0X6B,0X6C,0X6D,0X6E,0X6F,
    0X70,0X71,0X72,0X73,0X74,0X75,0X76,0X77,0X78,0X79,0X7A,0,0,0,0,0,
    0,0X61,0X62,0X63,0X64,0X65,0X66,0X67,0X68,0X69,0X6A,0X6B,0X6C,0X6D,0X6E,0X6F,
    0X70,0X71,0X72,0X73,0X74,0X75,0X76,0X77,0X78,0X79,0X7A,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};
unsigned char InvalidDnsNameTable[256] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,
    0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,
    1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,
    1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
};

#define ISVALIDDNSCHAR(_ch)  DnsNameTable[((unsigned char)_ch)]
#define ISINVALIDDNSCHAR(_ch)  InvalidDnsNameTable[((unsigned char)_ch)]

int
check_dns_name(uchar * domain, packet_type *lowerdomain)
{
    uchar len = domain[0], i;
    int tlen = 0;       //extra total len and type
    uchar *dst = lowerdomain->domain;
    hashval_t *hash = &(lowerdomain->hash[0]);
    
    lowerdomain->label_count = 0;
    lowerdomain->label[lowerdomain->label_count] = dst;
    lowerdomain->label_offsets[lowerdomain->label_count] = 0;
    lowerdomain->hash[0] = 5381;
    *dst = len;
    *hash = (((*hash << 5) + *hash) + *dst++);
    domain++;
    while (len != 0) {
        if (len > 63)
            return -1;
        for (i = 0; i < len; i++)       //num a-z A-Z -,and to lower
        {
            *dst = ISVALIDDNSCHAR(domain[i]);
            if (!(*dst))
                return -1;
            *hash = (((*hash << 5) + *hash) + *dst);
            dst++;
        }
        domain = domain + len;
        len = domain[0];
        lowerdomain->label_count++;
        lowerdomain->label[lowerdomain->label_count] = dst;
        lowerdomain->label_offsets[lowerdomain->label_count] = dst - lowerdomain->domain;
        lowerdomain->hash[lowerdomain->label_count] = 0;
        *dst = len;
        *hash = (((*hash << 5) + *hash) + *dst++);
        domain++;
    }
    for (i = 0; i < lowerdomain->label_count; i++)
    {
        lowerdomain->label_len[i] = dst - lowerdomain->label[i];
    }
    tlen = lowerdomain->label_len[0];
    if (tlen > 255)
        return -1;
    return tlen;
}


int
make_type_domain(uchar * domain, int dlen, int type, uchar * buffer)
{
    if (buffer == NULL || domain == NULL)
        return -1;
    buffer[0] = type;
    memcpy(buffer + 1, domain, dlen);
    return 0;
}


int
check_memcpy(uchar * to, uchar * from, int vlen)
{
    int i;
    for (i = 0; i < vlen; i++)
        if (to[i] != from[i])
            return -1;
    return 0;
}


//k and v both are in stack
//k td
//v mvalue.data
int
insert_kv_mem(struct rbtree *rbt, struct htable *ds, uchar * k, int klen, 
              int type, uchar * v, int vlen, int hijack, packet_type *lowerdomain)
{
    uchar *val = NULL;
    struct mvalue *mv = NULL, tmp = {0};
    int ret = -1;
    struct rbnode *pn = NULL;
    struct ttlnode tn = { 0 }, *tmp_tn = NULL;
    int idx;
    if (vlen < 0 || vlen > MAX_RECORD_SIZE)
        return -1;
    hashval_t *hash = &(lowerdomain->hash[0]);
    idx = get_pre_mem_hash(k, klen, hash);
    val = malloc(vlen);
    if (val == NULL)
        return -1;
    memcpy(val, v, vlen);
    mv = (struct mvalue *) v;
    ret = htable_insert(ds + idx, k, klen, type, val, 1, &tmp, hash);    //mem, replace
    if (ret == 2) {
        free(val);
    }
    if (rbt) {
        if (ret != 0) {
            pthread_spin_lock(&rbt->lock);
            tn.dlen = klen;
            //tmp get old data
            tn.exp = tmp.ttl;
            tn.type = type;
            tn.lowerdomain = NULL;
            tn.data = k;
            pn = find_node(rbt, &tn);
            //if update, we had delete tn in rbt
            //else update tn in rbt
            if (pn != NULL) {
                tmp_tn = delete_node(rbt, pn);
                if (tmp_tn) {
                    free(tmp_tn->lowerdomain);
                    free(tmp_tn);
                }
            }
            pthread_spin_unlock(&rbt->lock);
        }
    }
    if (mv->ttl == (MAX_TTL + 1)) {       //never expired
        return 0;
    }
    if (rbt == NULL) {
        return 0;
    }
    //data exists in htable, delete it in ttl tree, then insert
    pthread_spin_lock(&rbt->lock);
    ret = insert_into_ttltree(rbt, k, klen, type, mv->ttl, lowerdomain); //ttl expired tree
    pthread_spin_unlock(&rbt->lock);
    return 0;
}

////////////////////////////////////////////////////////////////////


int
get_level(uchar * itor)
{
    int lvl = 0;
    uchar len = itor[0];
    while (len != 0) {
        lvl++;
        itor += itor[0] + 1;
        len = itor[0];
        if (len > 63)
            return -1;
    }
    return lvl;
}


uchar *
fill_all_records_in_msg(struct hlpc * h, struct hlpf * hf, int idx)
{
    int step = 0;
    uint16_t txtlen;
    uchar *tmp = NULL, *to = hf->to, *from = hf->from;
    struct fillmsg *fm = (struct fillmsg *) (hf->to);
    fm->type = htons(hf->type);
    fm->dclass = htons(CLASS_IN);
    fm->ttl = htonl(hf->ttl - global_now);
    if (hf->ttl == MAX_TTL + 1)
        fm->ttl = htonl(hf->ttl - 1);
    to = to + sizeof(struct fillmsg);
    if (hf->type == A)
        step = 4;
    if (hf->type == AAAA)
        step = 16;
    switch (hf->type)           // no soa
    {
    case A:                    //idx not used
    case AAAA:
        fm->len = htons(step);
        memcpy(to, from, step);
        to = to + step;         //data
        break;
    case CNAME:
    case NS:
        idx++;
        h[idx].name = from;
        h[idx].off = to - hf->hdr;
        h[idx].ref = -1;
        h[idx].level = get_level(h[idx].name);
        h[idx].mt = 0;
        h[idx].len = hf->len;
        tmp = fill_name_in_msg(h, to, idx);
        fm->len = htons(tmp - to);
        to = tmp;
        break;
    case MX:
        memcpy(to, from, sizeof(uint16_t));     //ref
        from += sizeof(uint16_t);       //2
        to += sizeof(uint16_t);
        idx++;
        h[idx].name = from;
        h[idx].off = to - hf->hdr;
        h[idx].ref = -1;
        h[idx].level = get_level(h[idx].name);
        h[idx].mt = 0;
        h[idx].len = hf->len;
        tmp = fill_name_in_msg(h, to, idx);
        fm->len = htons(tmp - to + sizeof(uint16_t));
        to = tmp;
        break;
    case TXT:
        txtlen = *(uint16_t *) from;
        from += sizeof(uint16_t);       //len
        memcpy(to, from, txtlen);
        fm->len = htons(txtlen);
        to += txtlen;
        break;
    case SRV:
        memcpy(to, from, sizeof(uint16_t) * 3);
        from += sizeof(uint16_t) * 3;
        to = to + sizeof(uint16_t) * 3;
        idx++;
        h[idx].name = from;
        h[idx].off = to - hf->hdr;
        h[idx].ref = -1;
        h[idx].level = get_level(h[idx].name);
        h[idx].mt = 0;
        h[idx].len = hf->len;
        tmp = fill_name_in_msg(h, to, idx);
        fm->len = htons(tmp - to + sizeof(uint16_t) * 3);
        to = tmp;
        break;
    default:
        break;
    }
    return to;
}


//return the match length in the end of two strings.
//NOT include the end "."
int
reverse_compare(uchar * from, int flen, uchar * to, int tolen)
{
    uchar fi, ti, rec = 0;
    int match = 0;
    flen -= 2;                  //1 for strlen + 1, 1 for array in c
    tolen -= 2;
    fi = from[flen];
    ti = to[tolen];
    while (flen && tolen) {
        if (fi != ti)
            break;
        rec++;
        if (fi == (rec - 1))    //not include len itself
        {
            match++;
            rec = 0;
        }
        fi = from[--flen];
        ti = to[--tolen];
    }
    return match;
}


//imxg3.douban.com imxg3.douban.com.cdn20.com.
uchar *
fill_name_in_msg(struct hlpc * h, uchar * to, int idx)
{
    int i/*, mm = 0*/, m = 0, len, fill = 0, jump = 0, off = 0;
    const ushort base = 0xc000;
    uchar *itor = h[idx].name, *dn = NULL;
    if (idx == 0) {
        *(ushort *) to = htons(h[0].off + base);
        to += sizeof(ushort);
        return to;
    }
    len = h[idx].len;
    for (i = idx - 1; i >= 0; i--) {
        m = reverse_compare(h[i].name, h[i].len, h[idx].name,
                            len);
        if (m > h[i].mt) {
            h[idx].mt = m;      //max match
            h[idx].ref = i;
        }
    }
    if (h[idx].mt >= 0)
        fill = h[idx].level - h[idx].mt;
    else
        fill = h[idx].level;
    for (i = 0; i < fill; i++) {
        memcpy(to, itor, itor[0] + 1);  //len.label
        to = to + itor[0] + 1;
        itor = itor + itor[0] + 1;
    }
    len = 0;
    if (h[idx].ref >= 0) {
        dn = h[h[idx].ref].name;
        jump = h[h[idx].ref].level - h[idx].mt;
        for (i = 0; i < jump; i++) {
            len += dn[0] + 1;
            dn += dn[0] + 1;
        }
        off = h[h[idx].ref].off + len;
        *(ushort *) to = htons(off + base);
        to += 2;
    } else {
        to[0] = 0;              //no compression
        to++;
    }
    return to;
}


//jump from author.c
uchar *
fill_rrset_in_msg(struct hlpc * h, uchar * from, uchar * to, int n,
                  uchar * hdr)
{
    uchar type;
    int i, step = 0;
    uint16_t txtlen = 0;
    struct hlpf hf;
    int num = 0;
    struct mvalue *mv = NULL;
    type = from[0];
    from++;                     //type
    mv = (struct mvalue *) from;
    from = from + sizeof(struct mvalue);
    num = mv->num;
    if (num > MAX_MSG_SEG) {
        num = MAX_MSG_SEG;
    }
    hf.hdr = hdr;
    hf.ttl = mv->ttl;
    hf.type = type;
    if (type == A)
        step = 4;
    if (type == AAAA)
        step = 16;
    switch (type)               //7
    {
    case A:
    case AAAA:
        for (i = 0; i < num; i++) {
            to = fill_name_in_msg(h, to, n);
            hf.from = from;
            hf.to = to;
            //jump type and dclass
            //then we get ttl's position
            //plus hdr we get it's offset
            //only for A record
            to = fill_all_records_in_msg(h, &hf, n);
            from += step;
        }
        return to;
        break;
    case CNAME:                // cname must has 1 record
        to = fill_name_in_msg(h, to, n);
        hf.from = from;
        hf.to = to;
        to = fill_all_records_in_msg(h, &hf, n);
        return to;
        break;
    case NS:
        for (i = 0; i < num; i++) {
            to = fill_name_in_msg(h, to, n);
            hf.from = from;
            hf.to = to;
            hf.len = strlen((const char *)from) + 1;
            to = fill_all_records_in_msg(h, &hf, n);
            from += hf.len;//strlen((const char *)from) + 1;
        }
        return to;
        break;
    case MX:
        for (i = 0; i < num; i++) {
            to = fill_name_in_msg(h, to, n);
            hf.from = from;
            hf.to = to;
            hf.len = strlen((const char *)from) + 1;
            to = fill_all_records_in_msg(h, &hf, n + i);
            from += sizeof(uint16_t);   //jump ref
            from += hf.len;//strlen((const char *)from) + 1;   //jump name and tail 0
        }
        return to;
        break;
    case TXT:
        for (i = 0; i < num; i++) {
            to = fill_name_in_msg(h, to, n);
            hf.from = from;
            hf.to = to;
            to = fill_all_records_in_msg(h, &hf, n);
            txtlen = *(uint16_t *) from;
            from = from + txtlen + sizeof(uint16_t);
        }
        return to;
        break;
    case SRV:
        for (i = 0; i < num; i++) {
            to = fill_name_in_msg(h, to, n);
            hf.from = from;
            hf.to = to;
            hf.len = strlen((const char *)from) + 1;
            to = fill_all_records_in_msg(h, &hf, n);
            from += sizeof(uint16_t) * 3;       //pri wei port
            from += hf.len;//strlen((const char *)from) + 1;   //target
        }
        return to;
        break;
    default:
        printf("not support or error in fill msg\n");
        break;
    }
    return NULL;
}


uchar *
fill_header_in_msg(struct setheader * sh)
{
    uchar *itor = sh->itor;
    dnsheader *hdr = (dnsheader *) (sh->itor);
    qdns *qd;
    hdr->flags = 0;
    hdr->flags = SET_QR_R(hdr->flags);
    hdr->flags = SET_RA(hdr->flags);
    hdr->flags = DNS_GET16(hdr->flags);
    hdr->ancount = DNS_GET16(sh->an);
    hdr->nscount = DNS_GET16(sh->ns);
    hdr->arcount = 0; //DNS_GET16(0);
    itor += sizeof(dnsheader);
    itor = itor + sh->dlen;
    qd = (qdns *) itor;
    qd->type = DNS_GET16(sh->type);
    qd->dclass = DNS_GET16(CLASS_IN);
    itor += sizeof(qdns);
    return itor;
}


int
make_dns_msg_for_new(uchar * itor, ushort msgid, uchar * d, int len, ushort type)
{
    uchar *buf = itor;
    dnsheader *hdr = NULL;
    qdns *qd = NULL;
    hdr = (dnsheader *) buf;
    hdr->id = msgid;
    hdr->flags = htons(0x0100); //rd
    hdr->qdcount = htons(1);
    hdr->ancount = hdr->nscount = hdr->arcount = htons(0);
    buf += sizeof(dnsheader);
    memcpy(buf, d, len);
    buf[len - 1] = 0;
    buf += len;
    qd = (qdns *) buf;
    qd->type = htons(type);
    qd->dclass = htons(CLASS_IN);
    buf = buf + 4;
    return buf - itor;          //msg len
}


//a,ns,txt,cname,soa,srv,aaaa,mx
int
fill_rrset_in_buffer(uchar * buffer, uchar * label, uchar * hdr, int lth,
                     int type, struct hlpp *hlp)
{
    int mlen = 0;
    uint16_t len = lth;
//     uchar nsc[512] = { 0 };
    struct srv *from, *to;
    switch (type) {
    case A:
        mlen = 4;
        memcpy(buffer, label, 4);
        break;
    case NS:
        get_domain_from_msg(label, hdr, buffer, &mlen);
        to_lowercase(buffer, mlen);
        break;
    case CNAME:
        get_domain_from_msg(label, hdr, buffer, &mlen);
        to_lowercase(buffer, mlen);
        break;
    case SOA:                  //do nothing
        mlen = 0;
        break;
    case AAAA:
        mlen = 16;
        memcpy(buffer, label, 16);
        break;
    case MX:
        memcpy(buffer, label, 2);       //reference value
        label += 2;             //16bits
        buffer += 2;
        get_domain_from_msg(label, hdr, buffer, &mlen);
        mlen += 2;
        break;
    case SRV:
        from = (struct srv *) label;
        to = (struct srv *) buffer;
        to->pri = from->pri;    //net endian
        to->wei = from->wei;
        to->port = from->port;
        buffer += sizeof(uint16_t) * 3;
        label += sizeof(uint16_t) * 3;
        get_domain_from_msg(label, hdr, buffer, &mlen);
        mlen += sizeof(uint16_t) * 3;
        break;
    case TXT:                  //the only case that lth used
        memcpy(buffer, &len, sizeof(uint16_t)); //uint16_t
        buffer += sizeof(uint16_t);
        memcpy(buffer, label, lth);
        mlen = lth + sizeof(uint16_t);
        break;
    default:
        return -1;
    }
    return mlen;
}


//-1 error
//1  tc
//0 normal
//2 retry
int
check_an_msg(ushort flag, uchar * domain, int *bk)
{
    uint get = 0;
    flag = ntohs(flag);
    //printf("flag is 0x%x\n",flag);
    get = GET_QR(flag);
    if (get == QR_Q)            //query
    {
        printf("answer set Q sign\n");
        return -1;
    }
    get = GET_OPCODE(flag);     //ignore.
    get = GET_AA(flag);         //ignore
    get = GET_TC(flag);
    if (get == 1)
        return 1;               //tc
    get = GET_RD(flag);         //ignore
    get = GET_ERROR(flag);
    if ((get != 0) && (get != NAME_ERROR))      //soa
    {
        switch (get) {
        case SERVER_FAIL:
            //printf("2server fail\n");
            break;
            //case NAME_ERROR: SOA
            //*bk = 1;
            //printf("3name error\n");
            //break;
        case FORMAT_ERROR:
            //*bk = 1;
            //printf("1format error\n");
            break;
        case NOT_IMPL:
            //printf("4not implation\n");
            break;
        case REFUSED:
            //printf("5server refused\n");
            break;
        }
        return 2;
    }
    return 0;
}


int
check_out_msg(ushort cid, uchar * buf, int len)
{
    dnsheader *hdr = (dnsheader *) buf;
    hdr->id = cid;
    hdr->flags = 0;
    hdr->flags = htons(SET_QR_R(hdr->flags));
    return 0;
}


int
check_td(uchar * td)
{
    uchar type = td[0];
    uchar *itor = td + 1;
    uchar len = itor[0];
    if ((type != A) && (type != NS) && (type != CNAME))
        return -1;
    while (len != 0) {
        if (len > 50)
            return -1;
        itor = itor + len + 1;
        len = itor[0];
    }
    return 0;
}


//if ns is domain's child or child's child or...
//domain and ns are td format
//type.domain
//002,005,b,a,i,d,u,003,c,o,m
//003,n,s,'4',005,b,a,i,d,u,003,c,o,m
int
is_glue(uchar * domain, uchar * ns)
{
    uchar d, n;
    int dlen, nlen;
    dlen = strlen((const char *)domain);
    nlen = strlen((const char *)ns);
    dlen--;
    nlen--;
    if (dlen >= nlen)
        return 0;
    d = domain[dlen];
    n = ns[nlen];
    while (d == n) {
        dlen--;
        nlen--;
        if (dlen == 0)
            return 1;
        d = domain[dlen];
        n = ns[nlen];
    }
    return 0;
}


//First ensure the search name, if it has a cname, search the cname
//If we find it in fwd table, return the ip length, it's > 0
//Here we dont care the cname in fwd table, if somebody want to do this
//Add the main domain in fwd table
int
pre_find(mbuf_type *mbuf, struct htable *fwd, struct htable *ht,
         uchar * ip)
{
    uchar *td, *itor = NULL/*, type*/;
    int xlen = 0, dbg = 100;
//     uchar *buffer[2000];
    struct mvalue *mv = NULL;
    int td_len, new_td_len;
    hashval_t *hash, thash = 0;
    mbuf->qname = Q_DOMAIN;       //default
    if (mbuf->hascname == 1) {
        mbuf->qing = mbuf->qbuffer; //latest cname
        td_len = mbuf->qlen;
        td = mbuf->qbuffer;
        mbuf->qhash = &(mbuf->qbuffer_hash);
    } else {
        td_len = mbuf->dlen;
        mbuf->qing = mbuf->td;
        td = mbuf->td;
        mbuf->qhash = &(mbuf->lowerdomain.hash[0]);
    }
    hash = mbuf->qhash;
    xlen = htable_find(fwd, td, td_len, A, ip, 1900, NULL, hash);        //100 for struct mvalue
    if (xlen > 0) {
        ip = ip + xlen;
        mv = (struct mvalue *) ip;
        mv->num = 0;            //tail 0
        mv->ttl = 0;
        mv->hits = 0;
        mv->len = 0;
        return xlen;
    } else {
        uchar *new_td = mbuf->tdbuffer;
        if (mbuf->lowerdomain.label_count > 1) {
            new_td[0] = 1;
            new_td[1] = '*';
            new_td_len = mbuf->lowerdomain.label_len[mbuf->lowerdomain.label_count - 2];
            memcpy(new_td + 2, mbuf->lowerdomain.label[mbuf->lowerdomain.label_count - 2], new_td_len);
            thash = 0;
            int rlen = htable_find(fwd, new_td, new_td_len + 2, A, ip, 1900, NULL, &thash);
            if (rlen > 0) {
                ip = ip + rlen;
                mv = (struct mvalue *) ip;
                mv->num = 0;            //tail 0
                mv->ttl = 0;
                mv->hits = 0;
                mv->len = 0;
                return rlen;
            }
        }
    }
    if (mbuf->qtype == CNAME)     //query cname
        return 0;               //find nothing
    itor = mbuf->tempbuffer;
    while (1)                   //find cname
    {
        xlen = find_record_with_ttl(ht, td, td_len, CNAME, itor, 2000, NULL, hash);
        if (xlen > 0) {         //if domain has a cname, put it in qo->qbuffer
            mbuf->qname = Q_CNAME;
            mbuf->hascname = 1;
            mv = (struct mvalue *) itor;
            itor = itor + sizeof(struct mvalue);
            if (mv->len > (QBUFFER_SIZE - 1))
                return -1;
            memcpy(mbuf->qbuffer, itor, mv->len);
            mbuf->qing = mbuf->qbuffer;
            mbuf->qlen = td_len = mv->len;
            mbuf->qbuffer_hash = 0;
            hash = &(mbuf->qbuffer_hash);
            td = mbuf->qbuffer;
        } else
            break;
        if ((dbg--) == 0)
            return -1;
    }
    return 0;
}


//format of buff
//struct mvaule
//ttloff
//msg
int
transfer_record_to_msg(uchar * buff, uchar * key, uchar * msg, int msglen,
                       uint16_t * ttloff)
{
    uint16_t segs = ttloff[0], totallen = 0;
    uchar *itor = NULL;
    struct mvalue *mv = NULL;
    if (segs == 0 || segs > 100)
        return -1;
    totallen = msglen;
    totallen = totallen + segs * sizeof(uint16_t) + sizeof(struct mvalue);
    if (totallen > MAX_MSG_SIZE)
        return -1;
    itor = buff;
    mv = (struct mvalue *) itor;
    mv->seg = segs;
    mv->len = msglen;           //not include len of ttloff and mvalue
    itor = itor + sizeof(struct mvalue);        //jump mvalue
    memcpy(itor, ttloff + 1, sizeof(uint16_t) * segs);  //copy ttloff
    itor = itor + sizeof(uint16_t) * segs;      //jump ttloff
    memcpy(itor, msg, msglen);  //copy msg
    //seg and len are useful
    //ttl and hits are empty
    //num is invalid
    return 0;
}


///format of segment
//struct mvalue
//off.off.off.off...[mvalue->seg]
//msg
//off point ttl now
//we jump ttl and rdlength
//then we get raw A record data
//copy data from ipmsg to ipbuffer
//then copy data from ipbuffer to ipmsg
int
make_A_record_from_segment(uchar * ipmsg, uchar *iitor)
{
    int reallen = 0;
    uchar *ipto = NULL, *ipfrom = NULL;
    struct mvalue *mv = NULL;
    uint16_t off;
    int segs = 0, i;
    mv = (struct mvalue *) ipmsg;
    segs = mv->seg;
    ipto = iitor + sizeof(struct mvalue);
    for (i = 0; i < segs; i++) {
        off =
            *(uint16_t *) (ipmsg + sizeof(struct mvalue) +
                           i * sizeof(uint16_t));
        ipfrom = ipmsg + off;
        memcpy(ipto, ipfrom, 4);
        reallen += 4;
        ipto += 4;
    }
    mv->len = reallen;
    memcpy(iitor, ipmsg, sizeof(struct mvalue));
    return 0;
}


//we found some ns
//try to find their ip
int
retrive_ip(mbuf_type *mbuf, uchar * itor, int num, uchar * ip, struct htable *ht, int *fq)
{
    struct mvalue *mi = NULL;
    int i, xlen, iplen = IP_DATA_LEN;
    int got = 0;
    uchar *ipbuffer = mbuf->ipbuffer;
    *fq = 0;
    uchar *nstd, *iitor = ip;
    hashval_t hash;
    
    for (i = 0; i < num; i++) {
        xlen = strlen((const char *)itor) + 1;
        nstd = itor;
        itor = itor + xlen;
        hash = 0;
        xlen =
            find_record_with_ttl(ht, nstd, xlen, A, ipbuffer,
                                 iplen - sizeof(struct mvalue), NULL, &hash);
        if (xlen > 0) {
            mi = (struct mvalue *) ipbuffer;
            if (mi->seg > 0)    //segment
                make_A_record_from_segment(ipbuffer, iitor);
            else
                memcpy(iitor, ipbuffer, mi->len + sizeof(struct mvalue));
            iitor = iitor + mi->len + sizeof(struct mvalue);
            iplen = iplen - mi->len - sizeof(struct mvalue);
            got++;
        }
        if (xlen < 0)           //iplen is not enough
        {
            *fq = i;
            break;
        }
    }
    if (iitor != ip)            //found some ip
    {
        mi = (struct mvalue *) iitor;
        mi->num = 0;            //tail 0
        mi->ttl = 0;
        mi->hits = 0;
        mi->len = 0;
        return got;
    }
    return -1;                  //no ip
}


int
fill_extra_addr(uchar * ip)
{
    const char *extra[] = {
        g_nameservers[0], g_nameservers[1]
    };
    int i, n;
    struct mvalue *mv = NULL;
    n = sizeof(extra) / sizeof(extra[0]);
    mv = (struct mvalue *) ip;
    ip = ip + sizeof(struct mvalue);
    mv->num = 0;
    mv->ttl = 0;
    mv->hits = 0;
    mv->len = 0;
    for (i = 0; i < n; i++) {
        if (make_bin_from_str(ip, extra[i]) == 0) {
            mv->num++;
            mv->len += 4;       //4 bytes
            ip += 4;            //4 bytes
        }
    }
    mv = (struct mvalue *) ip;
    mv->num = 0;
    mv->ttl = 0;
    mv->hits = 0;
    mv->len = 0;
    return 0;
}


//ht,type,domain,dlen
int
find_addr(struct htable *fwd, struct htable *ht, mbuf_type *mbuf,
          uchar * ip, int forward)
{
    int ret, xlen = 0, dbg = 100;
    int first_query, i;
    struct mvalue *mv = NULL;
    uchar *td, *buffer = mbuf->tempbuffer, *itor = NULL, *glue = NULL;
    int td_len, diff_len;
    int ori_flag = 0;
    hashval_t thash, *hash;
    int label_count = 0;
    
    if (mbuf->qtimes > (MAX_TRY_TIMES - 3)) {
        fill_extra_addr(ip);
        return 0;
    }
    
    ret = pre_find(mbuf, fwd, ht, ip);
    if (ret > 0)                //find fwd
        return 0;
    else if (ret < 0)                //error
        return ret;
    else {
        if (forward) {
            fill_extra_addr(ip);
            return 0;
        }
    }
    //now we have domain or latest cname in qo->qing
    //point to qo->td or qo->qbuffer
    td = mbuf->qing;
    itor = td;
    hash = mbuf->qhash;
    td_len = mbuf->qlen;
    if (mbuf->hascname)
        ori_flag = 1;
    while (1)                   //put ns in itor(buffer), put ns'a in iitor(ip)
    {
        while (1) {
            ret = find_record_with_ttl(ht, itor, td_len, NS, buffer, IP_DATA_LEN, NULL, hash);    //ns do not
            if (ret > 0)
                break;
            if ((dbg--) == 0)   //if mess buffer
                return -1;
            if (ori_flag)
            {
                diff_len = itor[0] + 1;
                itor = itor + diff_len;  //parent, assert itor[1] < 64
                if (itor[0] == 0)   //root
                    return -1;
                
                td_len -= diff_len;
                thash = 0;
                hash = &thash;
            }
            else
            {
                label_count++;
                if (label_count >= mbuf->lowerdomain.label_count) // root
                    return -1;
                itor = mbuf->lowerdomain.label[label_count];
                td_len = mbuf->lowerdomain.label_len[label_count];
                hash = &(mbuf->lowerdomain.hash[label_count]);
            }
        }
        mv = (struct mvalue *) buffer;  //ns record in buffer
        glue = itor;            //data in td, real domain we get ns //key
        itor = buffer + sizeof(struct mvalue);  //data //value
        ret = retrive_ip(mbuf, itor, mv->num, ip, ht, &first_query);
        if ((ret > 0)) {
            if ((ret < mv->num) && (mbuf->qns == 1)) {
                mbuf->qns = 0;
                for (i = 0; i < first_query; i++) {
                    xlen = strlen((const char *)itor) + 1;
                    itor = itor + xlen;
                }
            } else
                return 0;
        }
        if (is_glue(glue, itor) != 1) //domain and it's ns,should be use itor,not buffer + sizeof(struct mvalue)
        {
            if (!ori_flag)
                ori_flag = 1;
            {
                xlen = strlen((const char *)itor) + 1;    //ns len
                if (xlen > (QBUFFER_SIZE - 1))
                    return -1;
                memcpy(mbuf->qbuffer, itor, xlen);
                mbuf->qbuffer_hash = 0;
                mbuf->qing = mbuf->qbuffer;
                mbuf->qhash = &(mbuf->qbuffer_hash);
                mbuf->qlen = xlen;
                hash = mbuf->qhash;
                td_len = mbuf->qlen;
                td = mbuf->qing;
            }
            itor = td;          //itor point to key now
        } else {                  //qbuffer and qing need NO change
            if (ori_flag)
            {
                diff_len = glue[0] + 1;
                itor = glue + diff_len;  //glue[0] is type,glue[1] is label length
                if (itor[0] == 0)   //root
                    return -1;
                td_len -= diff_len;
                thash = 0;
                hash = &thash;
            }
            else
            {
                label_count++;
                if (label_count >= mbuf->lowerdomain.label_count) // root
                    return -1;
                itor = mbuf->lowerdomain.label[label_count];
                td_len = mbuf->lowerdomain.label_len[label_count];
                hash = &(mbuf->lowerdomain.hash[label_count]);
            }
        }
        mbuf->qname = Q_NS;
        if ((dbg--) == 0)
            return -1;
    }
    return 0;
}


//same as find from mem
//for debug
int
check_qo(struct qoutinfo *qo)
{
    /* uchar type; */
    if (qo == NULL)
        return 0;
    if (qo->hascname > 1)
        printf("qo error\n");
    if (qo->td == NULL)
        printf("qo error2\n");
    return 0;
}


uchar *
dbg_print_label(uchar * label, int visible)
{
    uchar i, len = (uchar) (*label);
    if (visible == 1)
        for (i = 1; i < len + 1; i++)
            printf("%c", label[i]);
    return label + label[0] + 1;
}


uchar *
dbg_print_domain(uchar * hdr, uchar * itor)
{
    uchar len;
    uchar *tmp = NULL;
    ushort offset;
    int debug = 100;
    len = itor[0];
    if (len == 0) {
        printf("root\n");
        return 0;
    }
    offset = htons((ushort) * (ushort *) itor);
    if (IS_PTR(offset))
        itor = hdr + GET_OFFSET(offset);
    while (len != 0 && debug--) {
        if (IS_PTR(offset)) {
            tmp = itor + 2;
            itor = dbg_print_label(hdr + GET_OFFSET(offset), 1);
        } else
            itor = dbg_print_label(itor, 1);
        printf(".");
        len = itor[0];
        offset = htons((ushort) * (ushort *) itor);
    }
    printf("\n");
    if (tmp == NULL)
        tmp = itor + 1;
    return tmp;
}

void
dbg_print_ip(uchar * ip, enum rrtype type)
{
    int i;
    uint ipv4[4] = { 0 };
    for (i = 0; i < 4; i++)
        ipv4[i] = *(uchar *) (ip + i);
    if (type == A)
        printf("%u.%u.%u.%u\n", (unsigned short) ipv4[0], ipv4[1], ipv4[2],
               ipv4[3]);
    else if (type == AAAA) {
        for (i = 0; i < 8; i++) {
            if (ip[i * 2] != 0) {
                if (ip[i * 2] < 0x10)
                    printf("0");
                printf("%x", (uint) ip[i * 2]);
            }
            if (ip[i * 2 + 1] < 0x10)
                printf("0");
            printf("%x", (uint) ip[i * 2 + 1]);
            if (i != 7)
                printf(":");
        }
        printf("\n");
    } else
        printf("unknow type %d\n", type);
}


int
dbg_print_td(uchar * td)
{
    uchar c = td[0];
    printf("%d,", c);
    dbg_print_domain(NULL, td + 1);
    return 0;
}
