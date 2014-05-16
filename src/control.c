#define _POSIX_SOURCE
#include "author.h"
#include "datas.h"
#include "dns.h"
#include "control.h"
#include <assert.h>
#include <sys/types.h>
#include <signal.h>

int refresh_ttl_with_td(uchar *key, int len, int type, struct htable *ht, struct rbtree *ttlexp, packet_type *lowerdomain)
{
    pthread_spin_lock(&ttlexp->lock);
    printf("after delete, before insert, rbt size: %d\n", get_rbt_size(ttlexp));
    insert_into_ttltree(ttlexp, key, len, type, 0, lowerdomain);
    printf("after insert, rbt size: %d\n", get_rbt_size(ttlexp));
    pthread_spin_unlock(&ttlexp->lock);
    return 0;
}

int hijack(uchar *domain, uint16_t type, struct htable *ht, struct rbtree *ttlexp)
{
    if (!domain || domain[0] == '\0' || type <= 0 || type > 255) {
        kill(getpid(), SIGUSR1);
    } else {
        cache_flush(domain, type, ht, ttlexp);
    }

    /* struct mvalue *mv = (struct mvalue *)vbuffer; */
    /* mv->num = 0; */
    /* mv->ttl = 0; */
    /* mv->len = 0; */
    /* mv->seg = 0; */
    // get record content from 'cnt', cp to vitor, and insert k,v to ds
    // uchar *vitor = vbuffer + sizeof(struct mvalue);
    return 0;
}

int cache_flush(uchar *domain, uint16_t type, struct htable* ht, struct rbtree *ttlexp)
{
    printf("cache flush domain %s\n", domain);
//     uchar kbuffer[256] = { 0 };
    int dlen = strlen((const char *)domain) + 1;
    hashval_t hash = 0;
    packet_type lowerdomain;
    
    str_to_len_label(domain, dlen);
    check_dns_name(domain, &lowerdomain);
    domain = lowerdomain.domain;
//     make_type_domain(domain, dlen, type, kbuffer);
    int idx = get_pre_mem_hash(domain, dlen, &hash);
    uchar *val = htable_delete(ht + idx, domain, dlen, type, hash);
    if (val) {
        struct mvalue *tmp = (struct mvalue *)val;
        struct ttlnode tn = {0}, *tmp_tn = NULL;
        pthread_spin_lock(&ttlexp->lock);
        tn.dlen = dlen;
        tn.exp = tmp->ttl;
        tn.type = type;
        tn.data = domain;
        tn.lowerdomain = NULL;
        struct rbnode *pn = find_node(ttlexp, &tn);
        //if update, we had delete tn in rbt
        //else update tn in rbt
        if (pn != NULL) {
            tmp_tn = delete_node(ttlexp, pn);
            if (tmp_tn) {
                free(tmp_tn->lowerdomain);
                free(tmp_tn);
            } else {
                assert(0);
            }
        }
        pthread_spin_unlock(&ttlexp->lock);
        free(val);
        refresh_ttl_with_td(domain, dlen, type, ht, ttlexp, &lowerdomain);
    }
    /* uchar kbuffer[256] = {0}; */
    /* fix_tail((char*)domain); */
    /* int dlen = strlen((const char *)domain); */
    /* str_to_len_label(domain, dlen + 1); */
    /* make_type_domain(domain, dlen, type, kbuffer); */
    /* refresh_ttl_with_td(kbuffer, ht, ttlexp); */
    return 0;
}

