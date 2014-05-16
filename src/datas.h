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


//infrastructure memory manager
//0.red black tree

#ifndef _DATAS_H
#define _DATAS_H

#include "utils.h"
#include "dns.h"

// struct rbnode;
// struct entry;
// typedef int (comprbt) (void *, void *, void *);
// 
// #define RED (1)
// #define BLACK (0)
// 
// struct rbnode {
//     struct rbnode *parent;
//     struct rbnode *left;
//     struct rbnode *right;
//     int color;
//     void *key;
// };
// 
// struct rbtree {
//     struct rbnode *root, nil;
//     pthread_mutex_t lock;
//     uint size;
//     comprbt *c;
//     void *argv;
// };


struct rbtree *create_rbtree(comprbt * c, void *argv);
void *delete_node(struct rbtree *rbt, struct rbnode *nd);
int insert_node(struct rbtree *rbt, struct rbnode *nd);
struct rbnode *find_node(struct rbtree *rbt, void *key);
struct rbnode *min_node(struct rbtree *rbt);
uint get_rbt_size(struct rbtree *rbt);

//test only.
int rbtree_test(void);

#endif
