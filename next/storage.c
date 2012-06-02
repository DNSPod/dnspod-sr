//dilfish @ dnspod
//20120305

#include "storage.h"

//--------------------red black tree---------
static void
left_rotate(struct rbtree *rbt, struct rbnode *node)
{
    struct rbnode *tmp = node->right;
    node->right = tmp->left;
    if (tmp->left != &rbt->nil)
        tmp->left->parent = node;
    tmp->parent = node->parent;
    if (node->parent == &rbt->nil)
        rbt->root = tmp;
    else if (node == node->parent->left)
        node->parent->left = tmp;
    else
        node->parent->right = tmp;
    tmp->left = node;
    node->parent = tmp;
}


static void
right_rotate(struct rbtree *rbt, struct rbnode *node)
{
    struct rbnode *tmp = node->left;
    node->left = tmp->right;
    if (tmp->right != &rbt->nil)
        tmp->right->parent = node;
    tmp->parent = node->parent;
    if (node->parent == &rbt->nil)
        rbt->root = tmp;
    else if (node == node->parent->left)
        node->parent->left = tmp;
    else
        node->parent->right = tmp;
    tmp->right = node;
    node->parent = tmp;
}


static void
insert_fixup(struct rbtree *rbt, struct rbnode *nd)
{
    struct rbnode *tmp;
    while (nd->parent->color == RED) {
        if (nd->parent == nd->parent->parent->left) {
            tmp = nd->parent->parent->right;
            if (tmp->color == RED) {
                nd->parent->color = tmp->color = BLACK;
                nd->parent->parent->color = RED;
                nd = nd->parent->parent;
            } else {
                if (nd == nd->parent->right) {
                    nd = nd->parent;
                    left_rotate(rbt, nd);
                }
                nd->parent->color = BLACK;
                nd->parent->parent->color = RED;
                right_rotate(rbt, nd->parent->parent);
            }
        } else {
            tmp = nd->parent->parent->left;
            if (tmp->color == RED) {
                nd->parent->color = tmp->color = BLACK;
                nd->parent->parent->color = RED;
                nd = nd->parent->parent;
            } else {
                if (nd == nd->parent->left) {
                    nd = nd->parent;
                    right_rotate(rbt, nd);
                }
                nd->parent->color = BLACK;
                nd->parent->parent->color = RED;
                left_rotate(rbt, nd->parent->parent);
            }
        }
    }
    rbt->root->color = BLACK;
}


//find_node and delete_node are not safe
//delete node may return NULL.
struct rbnode *
find_node(struct rbtree *rbt, void *key)
{
    struct rbnode *nd = &rbt->nil;
    int i;
    nd = rbt->root;
    while (nd != &rbt->nil) {
        i = (rbt->c) (nd->key, key);
        if (i > 0)
            nd = nd->left;
        if (i < 0)
            nd = nd->right;
        if (nd == &rbt->nil)
            break;              //return null
        if (i == 0)
            return nd;
    }
    return NULL;
}


int
insert_node(struct rbtree *rbt, struct rbnode *nd)
{
    struct rbnode *tmp = &rbt->nil, *itor = rbt->root;
    //struct rbnode *nd = malloc(sizeof(struct rbnode));
    nd->left = nd->right = nd->parent = NULL;
    //nd->key = key;
    while (itor != &rbt->nil) {
        tmp = itor;
        if ((rbt->c) (itor->key, nd->key) > 0)
            itor = itor->left;
        else
            itor = itor->right;
    }
    nd->parent = tmp;
    if (tmp == &rbt->nil)
        rbt->root = nd;
    else {
        if ((rbt->c) (tmp->key, nd->key) > 0)
            tmp->left = nd;
        else
            tmp->right = nd;
    }
    nd->left = nd->right = &rbt->nil;
    nd->color = RED;
    insert_fixup(rbt, nd);
    rbt->size++;
    return 0;
}


static struct rbnode *
rbt_successor(struct rbtree *rbt, struct rbnode *nd)
{
    struct rbnode *min = &rbt->nil;
    if (nd->right != &rbt->nil) {
        min = nd->right;
        while (min->left != &rbt->nil)
            min = min->left;
        return min;
    }
    min = nd->parent;
    while ((min != &rbt->nil) && (nd == min->right)) {
        nd = min;
        min = min->parent;
    }
    return min;
}


static void
delete_fixup(struct rbtree *rbt, struct rbnode *nd)
{
    struct rbnode *tmp = &rbt->nil;
    while (nd != rbt->root && nd->color == BLACK)
        if (nd == nd->parent->left) {
            tmp = nd->parent->right;
            if (tmp->color == RED) {
                tmp->color = BLACK;
                nd->parent->color = RED;
                left_rotate(rbt, nd->parent);
                tmp = nd->parent->right;
            }
            if (tmp->left->color == BLACK && tmp->right->color == BLACK) {
                tmp->color = RED;
                nd = nd->parent;
            } else {
                if (tmp->right->color == BLACK) {
                    tmp->left->color = BLACK;
                    tmp->color = RED;
                    right_rotate(rbt, tmp);
                    tmp = nd->parent->right;
                }
                tmp->color = nd->parent->color;
                nd->parent->color = BLACK;
                tmp->right->color = BLACK;
                left_rotate(rbt, nd->parent);
                nd = rbt->root; //end while
            }
        } else {
            tmp = nd->parent->left;
            if (tmp->color == RED) {
                tmp->color = BLACK;
                nd->parent->color = RED;
                right_rotate(rbt, nd->parent);
                tmp = nd->parent->left;
            }
            if (tmp->right->color == BLACK && tmp->left->color == BLACK) {
                tmp->color = RED;
                nd = nd->parent;
            } else {
                if (tmp->left->color == BLACK) {
                    tmp->right->color = BLACK;
                    tmp->color = RED;
                    left_rotate(rbt, tmp);
                    tmp = nd->parent->left;
                }
                tmp->color = nd->parent->color;
                nd->parent->color = BLACK;
                tmp->left->color = BLACK;
                right_rotate(rbt, nd->parent);
                nd = rbt->root; //end while
            }
        }
    nd->color = BLACK;
}


struct rbnode *
min_node(struct rbtree *rbt)
{
    struct rbnode *tmp, *ret;
    tmp = rbt->root;
    ret = &rbt->nil;
    if (tmp == &rbt->nil)
        return NULL;
    while (tmp != &rbt->nil) {
        ret = tmp;
        tmp = tmp->left;
    }
    if (ret == &rbt->nil)
        return NULL;
    return ret;
}


//free node, return val
void *
delete_node(struct rbtree *rbt, void *key)
{
    void *val = NULL;
    struct rbnode *nd = NULL;
    struct rbnode *tmp, *itor;
    nd = find_node(rbt, key);
    if (nd == NULL || rbt == NULL) {
        printf("find node error\n");
        return NULL;
    }
    val = nd->key;
    if (nd->left == &rbt->nil || nd->right == &rbt->nil)
        tmp = nd;
    else
        tmp = rbt_successor(rbt, nd);
    if (tmp->left != &rbt->nil)
        itor = tmp->left;
    else
        itor = tmp->right;
    itor->parent = tmp->parent;
    if (tmp->parent == &rbt->nil)
        rbt->root = itor;
    else {
        if (tmp == tmp->parent->left)
            tmp->parent->left = itor;
        else
            tmp->parent->right = itor;
    }
    if (tmp != itor)
        nd->key = tmp->key;
    if (tmp->color == BLACK)
        delete_fixup(rbt, itor);
    //free(tmp);
    rbt->size--;
    return tmp;
}


struct rbtree *
create_rbtree(comprbt * c)
{
    struct rbtree *rbt = malloc(sizeof(struct rbtree));
    if (rbt == NULL)
        return NULL;
    rbt->c = c;
    rbt->size = 0;
    rbt->nil.parent = &(rbt->nil);
    rbt->nil.left = &(rbt->nil);
    rbt->nil.right = &(rbt->nil);
    rbt->nil.color = BLACK;
    rbt->nil.key = NULL;
    rbt->root = &rbt->nil;
    return rbt;
}


static int
deep_copy(uchar * from, uchar * to, int tlen)   //*to is big enough
{
    struct mvalue *mv = (struct mvalue *) from;
    int sz = mv->len + sizeof(struct mvalue);
    if (sz >= tlen)
        return -1;
    memcpy(to, from, sz);
    return sz;
}


//murmurhash
hashval_t
murmur(const void *key, int len)
{
    uint seed = 0x19871016;
    const uint m = 0x5bd1e995, r = 24;
    uint h1 = seed ^ len, h2 = 0;
    const uint *data = (const uint *) key;

    while (len >= 8) {
        uint k1 = *data++;
        k1 *= m;
        k1 ^= k1 >> r;
        k1 *= m;
        h1 *= m;
        h1 ^= k1;
        len -= 4;

        uint k2 = *data++;
        k2 *= m;
        k2 ^= k2 >> r;
        k2 *= m;
        h2 *= m;
        h2 ^= k2;
        len -= 4;
    }

    if (len >= 4) {
        uint k1 = *data++;
        k1 *= m;
        k1 ^= k1 >> r;
        k1 *= m;
        h1 *= m;
        h1 ^= k1;
        len -= 4;
    }

    switch (len) {
    case 3:
        h2 ^= ((uchar *) data)[2] << 16;
        //to through, no break
    case 2:
        h2 ^= ((uchar *) data)[1] << 8;
    case 1:
        h2 ^= ((uchar *) data)[0];
        h2 *= m;
    }
    h1 ^= h2 >> 18;
    h1 *= m;
    h2 ^= h1 >> 22;
    h2 *= m;
    h1 ^= h2 >> 17;
    h1 *= m;
    h2 ^= h1 >> 19;
    h2 *= m;

    uint64_t h = h1;
    h = (h << 32) | h2;
    return h;
}


/////////////////////////memory hash/////////////////////////////
struct htable *
htable_create(hashfunc * h, comparefunc * c, int size)
{
    int i, j;
    struct htable *ht = NULL;
    if (c == NULL)
        return NULL;
    if ((ht = malloc(sizeof(struct htable) * MULTI_HASH)) == NULL)
        return NULL;
    for (i = 0; i < MULTI_HASH; i++) {
        ht[i].h = h;
        if (h == NULL)
            ht[i].h = murmur;
        ht[i].c = c;
        ht[i].size = size;
        ht[i].now = 0;          //no need lock
        ht[i].mask = size - 1;
        pthread_mutex_init(&(ht[i].lock), NULL);
        if ((ht[i].table =
             malloc(sizeof(struct hdata) * ht[i].size)) == NULL) {
            for (j = 0; j < i; j++)
                free(ht[j].table);
            free(ht);
            return NULL;
        }
        for (j = 0; j < size; j++) {
            ht[i].table[j].list = NULL;
            pthread_mutex_init(&(ht[i].table[j].lock), NULL);
        }
    }
    return ht;
}


int
htable_find(struct htable *ht, uchar * key, int klen, uchar * buffer,
            int vlen)
{
    int idx, debug = DEBUG_TIMES, ret, off;
    struct hdata *hd = NULL;
    struct hentry *he = NULL;
    struct mvalue *mx = NULL;
    hashval_t h = (ht->h) (key, klen);
    idx = h & ht->mask;
    off = (h >> 32) & (MULTI_HASH - 1);
    ht = ht + off;
    hd = ht->table + idx;
    pthread_mutex_lock(&hd->lock);
    if (hd->list == NULL) {
        printf("empty error\n");
        pthread_mutex_unlock(&hd->lock);
        return -1;
    }
    he = hd->list;
    while (he != NULL) {
        if ((ht->c) (key, he->key) == 0) {
            if (buffer != NULL)
                ret = deep_copy(he->val, buffer, vlen);
            else
                ret = 1;        //successed
            pthread_mutex_unlock(&hd->lock);
            if (ret < 0)
                printf("copy error\n");
            return ret;
        }
        he = he->next;
        if (debug-- == 0) {
            printf("error in htable find\n");
            exit(0);
        }
    }
    pthread_mutex_unlock(&hd->lock);
    printf("find nothing\n");
    return -1;
}


struct hentry *
htable_delete(struct htable *ht, uchar * key, int klen)
{
    hashval_t h = (ht->h) (key, klen);
    int debug = DEBUG_TIMES;
    uint idx, off;
    struct hdata *hd = NULL;
    struct hentry *he = NULL, *prev = NULL;
    idx = h & ht->mask;
    off = (h >> 32) & (MULTI_HASH - 1);
    ht = ht + off;
    hd = ht->table + idx;
    pthread_mutex_lock(&hd->lock);
    if (hd->list == NULL) {
        pthread_mutex_unlock(&hd->lock);
        return NULL;
    }
    he = hd->list;
    if ((ht->c) (key, he->key) == 0) {
        hd->list = he->next;
        pthread_mutex_unlock(&hd->lock);
        pthread_mutex_lock(&ht->lock);
        ht->now--;
        pthread_mutex_unlock(&ht->lock);
        return he;
    }
    prev = he;
    he = he->next;
    while (he != NULL) {
        if ((ht->c) (key, he->key) == 0) {
            prev->next = he->next;
            pthread_mutex_unlock(&hd->lock);
            pthread_mutex_lock(&ht->lock);
            ht->now--;
            pthread_mutex_unlock(&ht->lock);
            return he;
        }
        prev = he;
        he = he->next;
        debug--;
        if (debug == 0) {
            printf("error in storage\n");
            exit(0);
        }
    }
    pthread_mutex_unlock(&hd->lock);
    return NULL;
}


//if conllision, replace old element by default.
//if replace is 1, replace it, return 1
//if replace is 0, drop it, return -1
//else return 0
int
htable_insert(struct htable *ht, struct hentry *he, int klen, int rpl)
{
    uchar *key = he->key;
    uchar *val = he->val;
    hashval_t hash;
    int ret, debug = DEBUG_TIMES;
    uint idx, off;
    struct hentry *cl = NULL;
    struct hdata *hd = NULL;    //slot header
    struct mvalue *pt = NULL;   //protect root and gtld
    pt = (struct mvalue *) val;
    if (pt->len > MAX_RECORD_SIZE)
        return -1;
    hash = ht->h(key, klen);
    idx = hash & ht->mask;
    off = (hash >> 32) & (MULTI_HASH - 1);
    ht = ht + off;
    hd = ht->table + idx;
    pthread_mutex_lock(&hd->lock);
    he->next = NULL;
    if (hd->list == NULL)
        hd->list = he;
    else {
        cl = hd->list;
        while (cl != NULL) {
            if ((ht->c) (cl->key, he->key) == 0)        //the exactly same elements
            {
                printf("dup\n");
                ret = -1;       //drop
                pthread_mutex_unlock(&hd->lock);
                //free(he);
                //rbt del
                return ret;     //replace
            }
            cl = cl->next;
            debug--;
            if (debug == 0) {
                printf("error in storage2\n");
                exit(0);
            }
        }
        he->next = hd->list;
        hd->list = he;
    }
    pthread_mutex_unlock(&hd->lock);
    pthread_mutex_lock(&ht->lock);
    ht->now++;
    pthread_mutex_unlock(&ht->lock);
    return 0;
}


int
domain_compare(const void *k1, const void *k2)
{
    uchar *itor1 = NULL, *itor2 = NULL;
    if (k1 == NULL)
        return -1;
    if (k2 == NULL)
        return 1;
    itor1 = (uchar *) k1;
    itor2 = (uchar *) k2;
    while (itor1[0] != 0) {
        if (itor1[0] > itor2[0])
            return 1;
        if (itor1[0] < itor2[0])
            return -1;
        itor1++;
        itor2++;
    }
    if (itor2[0] != 0)
        return -1;
    return 0;
}


int
compare_ttl(void *t1, void *t2)
{
    uint32_t tx1, tx2;
    if (t1 == NULL || t2 == NULL) {
        printf("fatal error in compare ttl\n");
        exit(0);
    }
    tx1 = *(uint32_t *) t1;
    tx2 = *(uint32_t *) t2;
    //printf("tx %u,%u\n",tx1,tx2);
    if (t1 > t2)
        return 1;
    if (t1 == t2)
        return 0;
    return -1;
}


int
record_insert(struct records *r, struct hlp *h)
{
    int ret;
    struct rbnode *node;
    struct hentry *he = NULL;
    if (r == NULL || h == NULL)
        return -1;
    he = malloc(sizeof(struct hentry) + h->len);
    if (he == NULL)
        return -1;
    he->ttl.key = h->ttl;
    h->ttl = NULL;
    pthread_mutex_lock(&r->lock);       //protect rbtree
    //printf("insert %d\n",*(uint32_t*)he->ttl.key);
    ret = insert_node(r->rbt, &he->ttl);
    if (ret < 0) {
        free(he);
        pthread_mutex_unlock(&r->lock);
        return -1;
    }
    he->val = h->val;
    memcpy(he->key, h->key, h->len);
    ret = htable_insert(r->ht, he, h->len, 0);
    if (ret < 0) {
        node = delete_node(r->rbt, &h->ttl);
        if (node == NULL) {
            printf("fatal error\n");
            exit(0);
        }
        free(he);
    }
    pthread_mutex_unlock(&r->lock);
    return 0;
}


int
record_find(struct records *r, struct hlp *h)
{
    return htable_find(r->ht, h->key, h->len, h->val, h->vlen);
}


int
record_delete(struct records *r, struct hlp *h)
{
    int ret;
    struct rbnode *nd, *node;
    struct hentry *he = NULL;
    pthread_mutex_lock(&r->lock);
    he = htable_delete(r->ht, h->key, h->len);
    if (he == NULL) {
        pthread_mutex_unlock(&r->lock);
        return -1;
    }
    nd = (struct rbnode *) he;
    node = delete_node(r->rbt, nd->key);
    if (node == NULL) {
        printf("fatal error delete node\n");
        exit(0);
    }
    //printf("node %d\n",*(uint32_t*)node->key);
    pthread_mutex_unlock(&r->lock);
    free(node->key);
    free(he->val);
    free(he);
    return 0;
}


int
ttl_find_and_delete(struct records *r, struct hlp *h)
{
    struct rbnode *node = NULL;
    struct hentry *he = NULL, *entry = NULL;
    node = min_node(r->rbt);
    if (node == NULL)
        return 0;
    entry = (struct hentry *) node;
    he = htable_delete(r->ht, entry->key, strlen(entry->key) + 1);
    if (he == NULL) {
        printf("fatal error\n");
        exit(0);
    }
    free(he);
    free(node->key);
    return 0;
}


int
main(int argc, char **argv)
{
#define INSERT_NUM (1000000)
    struct records rds;
    uchar key[50] = "test";
    int i, ret;
    struct hlp hlp;
    pthread_mutex_init(&rds.lock, NULL);
    rds.rbt = create_rbtree(compare_ttl);
    if (rds.rbt == NULL)
        printf("create rbtree error\n");
    rds.ht = htable_create(murmur, domain_compare, HASH_TABLE_SIZE);
    if (rds.ht == NULL)
        printf("create htable error\n");
    for (i = 0; i < INSERT_NUM; i++) {
        key[0] = i / 1000000 + '0';
        key[1] = ((i / 100000) % 10) + '0';
        key[2] = ((i / 10000) % 10) + '0';
        key[3] = ((i / 1000) % 10) + '0';
        key[4] = ((i / 100) % 10) + '0';
        key[5] = ((i / 10) % 10) + '0';
        key[6] = (i % 10) + '0';
        key[7] = 0;
        //printf("key is %s\n",key);
        hlp.key = key;
        hlp.len = strlen(key) + 1;
        hlp.ttl = malloc(sizeof(uint32_t));
        if (hlp.ttl == NULL) {
            printf("malloc ttl error\n");
            return -1;
        }
        *(hlp.ttl) = i * 3;
        hlp.val = malloc(200);
        if (hlp.val == NULL) {
            printf("alloc val error\n");
            return -1;
        }
        ret = record_insert(&rds, &hlp);
        if (ret < 0) {
            printf("insert error\n");
            return -1;
        }
    }
    sleep(5);
    for (i = 0; i < INSERT_NUM; i++) {
        key[0] = i / 1000000 + '0';
        key[1] = ((i / 100000) % 10) + '0';
        key[2] = ((i / 10000) % 10) + '0';
        key[3] = ((i / 1000) % 10) + '0';
        key[4] = ((i / 100) % 10) + '0';
        key[5] = ((i / 10) % 10) + '0';
        key[6] = (i % 10) + '0';
        key[7] = 0;
        hlp.key = key;
        hlp.len = strlen(key) + 1;
        record_delete(&rds, &hlp);
    }
    return 0;
}
