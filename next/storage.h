//dilfish @ dnspod
//double data structure
//hash for records
//rbtree for ttl

#ifndef _STORAGE_H
#define _STORAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>


#define DEBUG_TIMES (100)
#define HASH_TABLE_SIZE  (65536)
#define MULTI_HASH (8)
#define MAX_RECORD_SIZE (3000)

#define RED (1)
#define BLACK (0)


typedef unsigned char uchar;
typedef unsigned int uint;
typedef uint64_t hashval_t;

typedef hashval_t(hashfunc) (const void *data, int len);
typedef int (comparefunc) (const void *, const void *);
typedef int (comprbt) (void *, void *);


struct rbnode {
    struct rbnode *parent;
    struct rbnode *left;
    struct rbnode *right;
    int color;
    void *key;
};


struct hlp {
    uchar *key;
    int len;
    uint32_t *ttl;
    uchar *val;
    int vlen;                   //used by record_find
};


struct hentry {
    struct rbnode ttl;
    uchar *val;                 //has a header of struct mvalue entry
    struct hentry *next;
    uchar key[0];
};


struct hdata {
    struct hentry *list;
    pthread_mutex_t lock;
};


//header in value segment
struct mvalue {
    uint32_t len;
    uint32_t val;
    uchar data[0];
};


struct htable {
    pthread_mutex_t lock;       //protect now
    struct hdata *table;
    uint size, mask, now;
    hashfunc *h;
    comparefunc *c;
};


struct rbtree {
    struct rbnode *root, nil;
    pthread_mutex_t lock;
    uint size;
    comprbt *c;
};


//hash function,compare fucntion,hash slots size
struct htable *htable_create(hashfunc * h, comparefunc * c, int);
//htable, key,len of key,val,replace
int htable_insert(struct htable *, struct hentry *, int, int);
//htable,key,keylen
struct hentry *htable_delete(struct htable *ht, uchar *, int);
//htable,key,keylen,val,maxvallen
int htable_find(struct htable *, uchar *, int, uchar *, int);


//create new tree
struct rbtree *create_rbtree(comprbt * c);
//delete one node, return the key pointer
//if node don't exists, return NULL
void *delete_node(struct rbtree *rbt, void *);
//insert node, if node has existed, return -1
int insert_node(struct rbtree *rbt, struct rbnode *nd);
//find one node, return NULL or that node
struct rbnode *find_node(struct rbtree *rbt, void *key);
//minimum value node in tree
struct rbnode *min_node(struct rbtree *rbt);


struct records {
    struct rbtree *rbt;
    struct htable *ht;
    pthread_mutex_t lock;
};


#endif
