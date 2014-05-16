#ifndef __CONTROL_H__
#define __CONTROL_H__
#include "utils.h"
#include "storage.h"
#include "datas.h"
int cache_flush(uchar *domain, uint16_t type, struct htable* ht, struct rbtree *ttlexp);
int hijack(uchar *domain, uint16_t type, struct htable *ht, struct rbtree *ttlexp);
#endif
