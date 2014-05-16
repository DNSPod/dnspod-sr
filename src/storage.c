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


#include "storage.h"


const uint MAX_ELE_NUM = 1000000;


//////////////////////////memory chunk///////////////////////////
//push to tail
//pop from head
struct msgcache *
init_msgcache(int n)
{
    struct msgcache *mc = NULL;
    int pgsz;
    if (n < 1 || n > 5000)      //page size == 4k. 5000*4k == 20m
        return NULL;
    pgsz = getpagesize();
    if ((mc = malloc(sizeof(struct msgcache) + pgsz * n)) == NULL)
        return NULL;
    mc->size = pgsz * n;
    pthread_spin_init(&mc->lock, 0);
    mc->head = mc->tail = 0;
    mc->pkt = 0;
    return mc;
}


void
free_msgcache(struct msgcache *mc)
{
    if (mc != NULL)
        free(mc);
}

/////////////////////////////////////////////////////////////////


int
get_mvalue_len(uchar * val)
{
    struct mvalue *mv = (struct mvalue *) val;
    return mv->len;
}


//this should be defined in upper files
int
ttl_expired(uchar * val)
{
    struct mvalue *mv = (struct mvalue *) val;
    uint tx = global_now;
    if (mv->ttl == (MAX_TTL + 1))       //never expired
        return 0;
    if (mv->ttl < tx)
        return 1;
    return 0;
}


//use by memory hash and disk db
//copy data from storage to buffer
//after this, operate data will not need
//to lock database any more
static int
deep_copy(uchar * from, uchar * to, int tlen)   //*to is big enough
{
    struct mvalue *mv = (struct mvalue *) from;
    int sz = mv->len + sizeof(struct mvalue) + mv->seg * sizeof(uint16_t);
    if (sz >= tlen)
        return -1;
    mv->hits++;
    //printf("sz is %d\n",sz);
    memcpy(to, from, sz);
    return sz;
}


/////////////////////////memory hash/////////////////////////////
uint
get_pre_mem_hash(void *argv, int klen, hashval_t *hash)
{
    uint ret = 0;
    if (*hash == 0)
        *hash = nocase_char_hash_function(argv, klen);
    ret = (*hash / MULTI_HASH) % MULTI_HASH;
    return ret;
}


struct htable *
htable_create(hashfunc * h, comparefunc * c, int size, int num)
{
    int i, j;
    struct htable *ht = NULL;
    if (c == NULL)
        return NULL;
    if ((ht = malloc(sizeof(struct htable) * num)) == NULL)
        return NULL;
    for (i = 0; i < num; i++) {
        ht[i].h = h;
        if (h == NULL)
            ht[i].h = nocase_char_hash_function;
        ht[i].c = c;
        ht[i].size = size;
        ht[i].edata = NULL;
        ht[i].now = 0;          //no need lock
        ht[i].mask = size - 1;
        pthread_spin_init(&(ht[i].lock), 0);
        if ((ht[i].table =
             malloc(sizeof(struct hdata) * ht[i].size)) == NULL) {
            for (j = 0; j < i; j++)
                free(ht[j].table);
            free(ht);
            return NULL;
        }
        for (j = 0; j < size; j++) {
            ht[i].table[j].list = NULL;
            pthread_spin_init(&(ht[i].table[j].lock), 0);
        }
    }
    return ht;
}

void find_io_from_he(struct hentry *he, uint32_t limit, struct rbtree *rbt, int ttl_update)
{
    struct mvalue *mv;
    int i, val_num = SUPPORT_TYPE_NUM;
    uchar *val;
    time_t now = global_now;
    struct ttlnode tn, *ptn;
    struct rbnode *pn;
    
    assert(he->count > 0);
    
    for (i = 0; i< val_num; i++)
    {
        val = he->vals[i];
        if (val == NULL)
            continue;
        
        mv = (struct mvalue *)val;
        if ((mv->ttl > (now + ttl_update + 1)) && (mv->hits < limit))
        {
            tn.data = he->key;
            tn.type = support_type[i];
            tn.exp = mv->ttl;
            tn.dlen = strlen((const char *)he->key) + 1;
            tn.lowerdomain = NULL;
            pthread_spin_lock(&rbt->lock);
            pn = find_node(rbt, &tn);
            if (pn != NULL)
            {
                ptn = delete_node(rbt, pn);
                if (ptn != NULL)
                {
                    //printf("delete true\n");
                    free(ptn->lowerdomain);
                    free(ptn);
                } else
                    printf("delete error\n");
            }
            else
            {
                /* printf("find error\n"); */
                /* dbg_print_td(key); */
            }
            pthread_spin_unlock(&rbt->lock);
                    
            free(val);
            he->vals[i] = NULL;
            he->count--;
        }
        
        if (0 == he->count)
            break;
    }
    
    return;
}

int
htable_find_io(struct htable *ht, int idx,/* int off, uchar * buffer,
               uchar * key, int *klen, int vlen,*/ uint32_t limit,
               struct rbtree *rbt, int ttl_update)
{
    int /*ret,*/ debug = DEBUG_TIMES;
    struct hdata *hd;
    struct hentry *he, *prev = NULL, *tmp;
    
    if (idx > HASH_TABLE_SIZE)
        return -1;
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_spin_unlock(&hd->lock);
        return -1;
    }
    he = hd->list;
    while (he != NULL) {
        find_io_from_he(he, limit, rbt, ttl_update);
        if (0 == he->count)
        {
            tmp = he;
            if (NULL == prev)
                hd->list = he->next;
            else
                prev->next = he->next;
            he = he->next;
            free(tmp);
            hd->now--;
            pthread_spin_lock(&ht->lock);
            ht->now--;
            pthread_spin_unlock(&ht->lock);
        }
        else
        {
            prev = he;
            he = he->next;
        }
        debug--;
        if (debug == 0) {
            printf("error in storage...\n");
            exit(0);
        }
    }
    pthread_spin_unlock(&hd->lock);
    return -1;
}

uchar *get_val_from_he(struct hentry *he, int type)
{
    uchar *val;
    
    assert(he->count > 0);
    
    switch (type)
    {
        case A:
            val = he->val.A;
            break;
        case NS:
            val = he->val.NS;
            break;
        case CNAME:
            val = he->val.CNAME;
            break;
        case SOA:
            val = he->val.SOA;
            break;
        case MX:
            val = he->val.MX;
            break;
        case TXT:
            val = he->val.TXT;
            break;
        case AAAA:
            val = he->val.AAAA;
            break;
        case SRV:
            val = he->val.SRV;
            break;
        case PTR:
            val = he->val.PTR;
            break;
        default:
            val = NULL;
            break;
    }
    
    return val;
}

// read dirty
int
htable_find(struct htable *ht, uchar * key, int klen, int type, uchar * buffer, int vlen,
            struct mvalue *md, hashval_t *hashd)
{
    int idx, debug = DEBUG_TIMES, ret;
    struct hdata *hd = NULL;
    struct hentry *he = NULL;
    struct mvalue *mx = NULL;
    uchar *val;
    
    if (*hashd == 0)
        *hashd = (ht->h) (key, klen);
    idx = *hashd & ht->mask;
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_spin_unlock(&hd->lock);
        return -1;
    }
    he = hd->list;
    while (he != NULL) {
        if ((ht->c) (key, he->key) == 0) {
            val = get_val_from_he(he, type);
            if (NULL == val)
                ret = -1;
            else if (buffer != NULL)
                ret = deep_copy(val, buffer, vlen);
            else {
                if (md != NULL) {
                    mx = (struct mvalue *)val;
                    *md = *mx;  //meta data
                }
                ret = 1;        //successed
            }
            pthread_spin_unlock(&hd->lock);
            return ret;
        }
        he = he->next;
        if (debug-- == 0) {
            printf("error in htable find\n");
            exit(0);
        }
    }
    pthread_spin_unlock(&hd->lock);
    return -1;
}

int
find_list_io_from_he(struct hentry *he, int *typeoff, uchar **buffer)
{
    int i, val_num = SUPPORT_TYPE_NUM;
    uchar *val;
    
    assert(he->count > 0);
    
    for (i = *typeoff; i < val_num; i++)
    {
        val = he->vals[i];
        if (val == NULL)
            continue;
        
        *buffer = val;
        *typeoff = i;
        return 1;
    }
    
    return 0;
}

int
htable_find_list_io(struct htable *ht, int idx, int off, int *typeoff, uchar **buffer)
{
    int debug = DEBUG_TIMES, ret;
    struct hdata *hd = NULL;
    struct hentry *he = NULL;
    
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_spin_unlock(&hd->lock);
        return -1;
    }
    he = hd->list;
    while (he != NULL) {
        if (off == 0) {
            ret = find_list_io_from_he(he, typeoff, buffer);
            pthread_spin_unlock(&hd->lock);
            return ret;
        }
        off--;
        he = he->next;
        if (debug-- == 0) {
            printf("error in htable find list io\n");
            exit(0);
        }  
    }
    pthread_spin_unlock(&hd->lock);
    return -1;
}

int
get_list_val_from_he(struct hentry *he, int typeoff, uchar **buffer)
{
    uchar *val;
    
    assert(he->count > 0);
    
    val = he->vals[typeoff];
    *buffer = val;
    if (NULL == val)
        return -1;
    return 1;
}

int
htable_find_list(struct htable *ht, uchar *key, int typeoff, int idx, uchar **buffer)
{
    int debug = DEBUG_TIMES/*, ret*/;
    struct hdata *hd = NULL;
    struct hentry *he = NULL;
    mbuf_type *mbuf;
    
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_spin_unlock(&hd->lock);
        return -1;
    }
    he = hd->list;
    while (he != NULL) {
        mbuf = (mbuf_type *)(he->vals[typeoff]);
        if ((mbuf != NULL) && ((ht->c) (key, mbuf->qing) == 0)) {
            *buffer = (uchar *)mbuf;
            pthread_spin_unlock(&hd->lock);
            return 1;
        }
        he = he->next;
        if (debug-- == 0) {
            printf("error in htable find\n");
            exit(0);
        }
    }
    pthread_spin_unlock(&hd->lock);
    return -1;
}

uchar *delete_val_from_he(struct hentry *he, int type)
{
    uchar **oval, *val = NULL;
    
    assert(he->count > 0);
    
    switch (type)
    {
        case A:
            oval = &(he->val.A);
            break;
        case NS:
            oval = &(he->val.NS);
            break;
        case CNAME:
            oval = &(he->val.CNAME);
            break;
        case SOA:
            oval = &(he->val.SOA);
            break;
        case MX:
            oval = &(he->val.MX);
            break;
        case TXT:
            oval = &(he->val.TXT);
            break;
        case AAAA:
            oval = &(he->val.AAAA);
            break;
        case SRV:
            oval = &(he->val.SRV);
            break;
        case PTR:
            oval = &(he->val.PTR);
            break;
        default:
            return NULL;
            break;
    }
    
    if (*oval != NULL)
    {
        val = *oval;
        *oval = NULL;
        he->count--;
    }
    
    return val;
}

uchar *
htable_delete(struct htable *ht, uchar * key, int klen, int type, hashval_t hashd)
{
    hashval_t h = (hashd) ? (hashd) : ((ht->h) (key, klen));
    int idx = h & ht->mask, debug = DEBUG_TIMES;
    struct hdata *hd = NULL;
    struct hentry *he = NULL, *prev = NULL;
    hd = ht->table + idx;
    uchar *val;
    
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_spin_unlock(&hd->lock);
        return NULL;
    }
    he = hd->list;
    while (he != NULL) {
        if ((ht->c) (key, he->key) == 0) {
            val = delete_val_from_he(he, type);
            if (0 == he->count)
            {
                if (NULL == prev)
                    hd->list = he->next;
                else
                    prev->next = he->next;
                free(he);
                hd->now--;
                pthread_spin_lock(&ht->lock);
                ht->now--;
                pthread_spin_unlock(&ht->lock);
            }
            pthread_spin_unlock(&hd->lock);
            return val;
        }
        prev = he;
        he = he->next;
        debug--;
        if (debug == 0) {
            printf("error in storage\n");
            exit(0);
        }
    }
    pthread_spin_unlock(&hd->lock);
    return NULL;
}

uchar *delete_list_val_from_he(struct hentry *he, int typeoff)
{
    uchar **oval, *val = NULL;
    
    assert(he->count > 0);
    
    oval = &(he->vals[typeoff]);
    
    if (*oval != NULL)
    {
        val = *oval;
        *oval = NULL;
        he->count--;
    }
    
    return val;
}

uchar *
htable_delete_list_io(struct htable *ht, int typeoff, int idx, int off)
{
    int debug = DEBUG_TIMES;
    struct hdata *hd = NULL;
    struct hentry *he = NULL, *prev = NULL;
    uchar *val;
    
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_spin_unlock(&hd->lock);
        return NULL;
    }
    he = hd->list;
    while (he != NULL) {
        if (off == 0) {
            val = delete_list_val_from_he(he, typeoff);
            if (0 == he->count)
            {
                if (NULL == prev)
                    hd->list = he->next;
                else
                    prev->next = he->next;
                free(he);
                hd->now--;
                pthread_spin_lock(&ht->lock);
                ht->now--;
                pthread_spin_unlock(&ht->lock);
            }
            pthread_spin_unlock(&hd->lock);
            return val;
        }
        off--;
        prev = he;
        he = he->next;
        if (debug-- == 0) {
            printf("error in htable find list io\n");
            exit(0);
        }  
    }
    pthread_spin_unlock(&hd->lock);
    return NULL;
}

uchar *
htable_delete_list(struct htable *ht, uchar *key, int typeoff, int idx)
{
    int debug = DEBUG_TIMES;
    struct hdata *hd = NULL;
    struct hentry *he = NULL, *prev = NULL;
    uchar *val;
    
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_spin_unlock(&hd->lock);
        return NULL;
    }
    he = hd->list;
    while (he != NULL) {
        if ((ht->c) (key, he->key) == 0) {
            val = delete_list_val_from_he(he, typeoff);
            if (0 == he->count)
            {
                if (NULL == prev)
                    hd->list = he->next;
                else
                    prev->next = he->next;
                free(he);
                hd->now--;
                pthread_spin_lock(&ht->lock);
                ht->now--;
                pthread_spin_unlock(&ht->lock);
            }
            pthread_spin_unlock(&hd->lock);
            return val;
        }
        prev = he;
        he = he->next;
        if (debug-- == 0) {
            printf("error in htable find list io\n");
            exit(0);
        }  
    }
    pthread_spin_unlock(&hd->lock);
    return NULL;
}


// A, NS, CNAME, SOA, MX, TXT, AAAA, SRV, PTR
int append_value_to_he(struct hentry *he, uchar *val, int type, int replace,
                        struct mvalue *mv)
{
    int ret;
    uchar **oval;
    
    switch (type)
    {
        case A:
            oval = &(he->val.A);
            break;
        case NS:
            oval = &(he->val.NS);
            break;
        case CNAME:
            oval = &(he->val.CNAME);
            break;
        case SOA:
            oval = &(he->val.SOA);
            break;
        case MX:
            oval = &(he->val.MX);
            break;
        case TXT:
            oval = &(he->val.TXT);
            break;
        case AAAA:
            oval = &(he->val.AAAA);
            break;
        case SRV:
            oval = &(he->val.SRV);
            break;
        case PTR:
            oval = &(he->val.PTR);
            break;
        default:
            return -1;
            break;
    }
    
    if (*oval != NULL)
    {
        if (replace)
        {
            if (mv != NULL)     //get old meta data
                *mv = *(struct mvalue *) (*oval);
            if ((mv != NULL) && (mv->ttl != (MAX_TTL + 1)))
            {
                free(*oval);
                *oval = val;
                ret = 1;
            }
            else
            {
                ret = 2;
            }
        }
        else
        {
            ret = -1;
        }
    }
    else
    {
        he->count++;
        *oval = val;
        ret = 0;
    }
    return ret;
}

//if conllision, replace old element by default.
//if replace is 1, replace it, return 1
//if replace is 0, drop it, return -1
//else return 0
int
htable_insert(struct htable *ht, uchar * key, int klen, int type, uchar * val, int replace,
              struct mvalue *mv, hashval_t *hashd)
{
    int idx, ret, debug = DEBUG_TIMES;
    struct hentry *he = NULL, *cl = NULL;
    struct hdata *hd = NULL;
    /* struct mvalue *pt = NULL;   //protect root and gtld */
    uchar dlen = klen;
    he = malloc(sizeof(struct hentry) + dlen);
    if (he == NULL) {
        printf("oom\n");
        return -1;
    }
    memset(he, 0, sizeof(struct hentry));
    memcpy(he->key, key, dlen);
    if (*hashd == 0) {
        *hashd = ht->h(key, klen);
    }
    idx = *hashd & ht->mask;
    //printf("hash %u,idx is %d\n",hash,idx);
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL)
    {
        append_value_to_he(he, val, type, replace, NULL);
        hd->now = 1;
        hd->list = he;
    }
    else {
        cl = hd->list;
        while (cl != NULL) {
            if ((ht->c) (cl->key, he->key) == 0)        //the exactly same elements
            {
                ret = append_value_to_he(cl, val, type, replace, mv);
                pthread_spin_unlock(&hd->lock);
                free(he);
                return ret;     //replace
            }
            cl = cl->next;
            debug--;
            if (debug == 0) {
                printf("error in storage2\n");
                exit(0);
            }
        }
        append_value_to_he(he, val, type, replace, NULL);
        he->next = hd->list;
        hd->list = he;
        hd->now++;
    }
    pthread_spin_unlock(&hd->lock);
    pthread_spin_lock(&ht->lock);
    ht->now++;
    pthread_spin_unlock(&ht->lock);
    return 0;
}

int
htable_insert_list(struct htable *ht, uchar * key, int klen, int type, uchar * val, int replace,
              struct mvalue *mv, hashval_t *hashd)
{
    int idx, ret, debug = DEBUG_TIMES;
    struct hentry *he = NULL, *cl = NULL, *prev = NULL;
    struct hdata *hd = NULL;
    /* struct mvalue *pt = NULL;   //protect root and gtld */
    uchar dlen = klen;
    he = malloc(sizeof(struct hentry) + dlen);
    if (he == NULL) {
        printf("oom\n");
        return -1;
    }
    memset(he, 0, sizeof(struct hentry));
    memcpy(he->key, key, dlen);
    if (*hashd == 0) {
        *hashd = ht->h(key, klen);
    }
    idx = *hashd & ht->mask;
    //printf("hash %u,idx is %d\n",hash,idx);
    hd = ht->table + idx;
    pthread_spin_lock(&hd->lock);
    if (hd->list == NULL)
    {
        append_value_to_he(he, val, type, replace, NULL);
        hd->now = 1;
        hd->list = he;
    }
    else {
        cl = hd->list;
        while (cl != NULL) {
            if ((ht->c) (cl->key, he->key) == 0)        //the exactly same elements
            {
                ret = append_value_to_he(cl, val, type, replace, mv);
                pthread_spin_unlock(&hd->lock);
                free(he);
                return ret;     //replace
            }
            prev = cl;
            cl = cl->next;
            debug--;
            if (debug == 0) {
                printf("error in storage3\n");
                exit(0);
            }
        }
        append_value_to_he(he, val, type, replace, NULL);
        prev->next = he;
        hd->now++;
    }
    pthread_spin_unlock(&hd->lock);
    pthread_spin_lock(&ht->lock);
    ht->now++;
    pthread_spin_unlock(&ht->lock);
    return 0;
}


int
find_record_with_ttl(struct htable *ht, uchar * key, int klen, int type, uchar *val, int vlen,
                     struct mvalue *md, hashval_t *hash)
{
    int idx, ret;
    uchar *oval;
    idx = get_pre_mem_hash(key, klen, hash);
    ret = htable_find(ht + idx, key, klen, type, val, vlen, md, hash);
    if (ret > 0) {
        if (ttl_expired(val) == 1) {
            oval = htable_delete(ht + idx, key, klen, type, *hash);
            if (oval != NULL)
                free(oval);
        } else {
            return ret;
        }
    }
    return -1;
}


/////////////////////////////////////////////////////////////////
////////////////////////////////dbg//////////////////////////////
#define THREADX (5)
#define NUMX (10000)
struct st_hlp {
    struct htable *ht;
    int idx;
};


void *
st_th(void *arg)
{
    int i, idx;
    uchar key[50] = { 0 };
    int klen;
    uchar *val = NULL;
    int pre = 0;
//     struct hentry *he = NULL;
    uchar *oval;
    struct htable *ht;
    struct st_hlp *sh = (struct st_hlp *) arg;
    hashval_t hash;
    idx = sh->idx;
    ht = sh->ht;
    for (i = idx * NUMX; i < (idx + 1) * NUMX; i++) {
        hash = 0;
        sprintf((char *)key, "%dkey", i);
        val = malloc(50);
        sprintf((char *)val, "%dval", i);
        //printf("%d,%s,%s\n",idx,key,val);
        klen = strlen((const char *)key) + 1;
        pre = get_pre_mem_hash(key, klen, &hash);
        htable_insert(ht + pre, key, klen, A, val, 0, NULL, &hash);
    }
    if (idx == (THREADX - 1))
        idx = -1;
    sleep(2);
    for (i = (idx + 1) * NUMX; i < (idx + 2) * NUMX; i++) {
        hash = 0;
        sprintf((char *)key, "%dkey", i);
        klen = strlen((const char *)key) + 1;
        pre = get_pre_mem_hash(key, klen, &hash);
        oval = htable_delete(ht + pre, key, klen, A, hash);
        if (oval == NULL) {
            printf("error in test %s,%d,%d\n", key, idx, i);
        }
        else
            free(oval);
    }
    sleep(5);
    return NULL;
}


int
storage_test(void)
{
    struct htable *ht = NULL;
    pthread_t pt[THREADX];
    int i;
    struct st_hlp sh[THREADX];
    //ht = htable_create(NULL,dict_comp_str_equ,HASH_TABLE_SIZE,MULTI_HASH);
    if (ht == NULL)
        dns_error(0, "create htable error");
    for (i = 0; i < THREADX; i++) {
        sh[i].ht = ht;
        sh[i].idx = i;
        if (pthread_create(pt + i, NULL, st_th, sh + i))
            dns_error(0, "create pthread");
    }
    for (i = 0; i < THREADX; i++)
        pthread_join(pt[i], NULL);
    sleep(2);
    return 0;
}
