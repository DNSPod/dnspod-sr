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


#include "datas.h"


//!!!!!!!!!!!!!could NOT used in multithread env!!!!!!!!!!!!!!!!!!


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
    //pthread_mutex_lock(&(rbt->lock));
    nd = rbt->root;
    while (nd != &rbt->nil) {
        i = (rbt->c) (nd->key, key, rbt->argv);
        if (i > 0)
            nd = nd->left;
        if (i < 0)
            nd = nd->right;
        if (nd == &rbt->nil)
            break;              //return null
        if (i == 0) {
            //pthread_mutex_unlock(&(rbt->lock));
            return nd;
        }
    }
    //pthread_mutex_unlock(&(rbt->lock));
    return NULL;
}


int
insert_node(struct rbtree *rbt, struct rbnode *pnd)
{
    struct rbnode *tmp = &rbt->nil, *itor = rbt->root;
    struct rbnode *nd = malloc(sizeof(struct rbnode));
    if (nd == NULL)
        return -1;
    *nd = *pnd;
    //pthread_mutex_lock(&(rbt->lock));
    while (itor != &rbt->nil) {
        tmp = itor;
        if ((rbt->c) (itor->key, nd->key, rbt->argv) > 0)
            itor = itor->left;
        else
            itor = itor->right;
    }
    nd->parent = tmp;
    if (tmp == &rbt->nil)
        rbt->root = nd;
    else {
        if ((rbt->c) (tmp->key, nd->key, rbt->argv) > 0)
            tmp->left = nd;
        else
            tmp->right = nd;
    }
    nd->left = nd->right = &rbt->nil;
    nd->color = RED;
    insert_fixup(rbt, nd);
    rbt->size++;
    //pthread_mutex_unlock(&(rbt->lock));
    /* printf("\t\t\t\t\t\t\tafter insert, rbt size: %d\n", get_rbt_size(rbt)); */
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
    //pthread_mutex_lock(&(rbt->lock));
    tmp = rbt->root;
    ret = &rbt->nil;
    if (tmp == &rbt->nil) {
        //pthread_mutex_unlock(&(rbt->lock));
        return NULL;
    }
    while (tmp != &rbt->nil) {
        ret = tmp;
        tmp = tmp->left;
    }
    if (ret == &rbt->nil) {
        //pthread_mutex_unlock(&(rbt->lock));
        return NULL;
    }
    //pthread_mutex_unlock(&(rbt->lock));
    return ret;
}


//free node, return val
void *
delete_node(struct rbtree *rbt, struct rbnode *nd)
{
    struct ttlnode *val = NULL;
    struct rbnode *ret = nd;
    struct rbnode *tmp, *itor;
    if (nd == NULL || rbt == NULL)
        return NULL;
    val = nd->key;
    /* printf("delete node ttl: %d ", val->exp); */
    /* dbg_print_td(val->data); */
    //pthread_mutex_lock(&(rbt->lock));
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
    if (ret == NULL)
        printf("ret is null\n");
    free(tmp);
    rbt->size--;
    //pthread_mutex_unlock(&(rbt->lock));
    /* printf("\t\t\t\t\t\t\tafter delete, rbt size: %d\n", get_rbt_size(rbt)); */
    return val;
}


struct rbtree *
create_rbtree(comprbt * c, void *argv)
{
    struct rbtree *rbt = malloc(sizeof(struct rbtree));
    if (rbt == NULL)
        return NULL;
    rbt->argv = argv;
    rbt->c = c;
    rbt->size = 0;
    pthread_spin_init(&rbt->lock, 0);
    rbt->nil.parent = &(rbt->nil);
    rbt->nil.left = &(rbt->nil);
    rbt->nil.right = &(rbt->nil);
    rbt->nil.color = BLACK;
    rbt->nil.key = NULL;
    rbt->root = &rbt->nil;
    return rbt;
}


uint
get_rbt_size(struct rbtree * rbt)
{
    return rbt->size;
}


int
free_rbtree(struct rbtree *rbt)
{
    if (get_rbt_size(rbt) > 0)
        return -1;
    free(rbt);
    return 0;
}


//---------------rbtree debug------------------------------------//
int
rbtree_test(void)
{
    int i, j, len, slice, ret;
    struct rbnode node, *pn = NULL;
    struct ttlnode *tn = NULL;
    struct rbtree *rbt = NULL;
    rbt = create_rbtree(rbt_comp_ttl_gt, NULL);
    if (rbt == NULL)
        dns_error(0, "create rbtree");
    node = rbt->nil;            //nil
    slice = 8000000;
    //for(i = 0;i < n;i ++)
    //{
    for (j = 0; j < slice; j++) {
        len = random() % 30;
        tn = malloc(sizeof(struct ttlnode) + len);
        if (tn == NULL)
            printf("oom\n");
        tn->exp = j;
        for (i = 0; i < len; i++)
            tn->data[i] = 'a' + i;
        node.key = tn;
        ret = insert_node(rbt, &node);
        if (ret != 0)
            printf("insert error\n");
    }
    printf("insert all\n");
    sleep(2);
    for (j = 0; j < slice; j++) {
        pn = min_node(rbt);
        if (pn != NULL) {
            tn = delete_node(rbt, pn);
            free(tn);
        } else
            printf("error\n");
    }
    printf("delete all\n");
    sleep(5);
    //}
    if (free_rbtree(rbt) != 0)
        dns_error(0, "free");
    //get_time_usage(&tv,0);
    return 0;
}
