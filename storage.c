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
struct msgcache* init_msgcache(int n)
{
 struct msgcache *mc = NULL;
 int i,len,pgsz;
 char *itor = NULL;
 if(n < 1 || n > 5000) //page size == 4k. 5000*4k == 20m
	return NULL;
 pgsz = getpagesize();
 if((mc = malloc(sizeof(struct msgcache) + pgsz * n)) == NULL)
	return NULL;
 mc->size = pgsz * n;
 pthread_mutex_init(&mc->lock,NULL);
 mc->head = mc->tail = 0;
 return mc;
}


void free_msgcache(struct msgcache *mc)
{
 if(mc != NULL)
	 free(mc);
}
/////////////////////////////////////////////////////////////////


int get_mvalue_len(uchar *val)
{
 struct mvalue *mv = (struct mvalue*)val;
 return mv->len;
}


//this should be defined in upper files
int ttl_expired(uchar *val)
{
 struct mvalue *mv = (struct mvalue*)val;
 uint tx = global_now;
 if(mv->ttl == (MAX_TTL + 1)) //never expired
	return 0;
 if(mv->ttl < tx)
	 return 1;
 return 0;
}


//use by memory hash and disk db
//copy data from storage to buffer
//after this, operate data will not need
//to lock database any more
static int deep_copy(uchar *from,uchar *to,int tlen) //*to is big enough
{
 struct mvalue *mv = (struct mvalue*)from;
 int sz = mv->len + sizeof(struct mvalue) + mv->seg * sizeof(uint16_t);
 if(sz >= tlen)
	return -1;
 mv->hits ++;
 //printf("sz is %d\n",sz);
 memcpy(to,from,sz);
 return sz;
}


/////////////////////////memory hash/////////////////////////////
uint get_pre_mem_hash(void *argv)
{
 uint ret = 0;
 hashval_t h = nocase_char_hash_function(argv);
 ret = (h / MULTI_HASH) % MULTI_HASH;
 return ret;
}


struct htable* htable_create(hashfunc *h,comparefunc *c,int size,int num)
{
 int i,j;
 struct htable *ht = NULL;
 if(c == NULL)
	return NULL;
 if((ht = malloc(sizeof(struct htable) * num)) == NULL)
	return NULL;
 for(i = 0;i < num;i ++)
	{
	 ht[i].h = h;
	 if(h == NULL)
		ht[i].h = nocase_char_hash_function;
	 ht[i].c = c;
	 ht[i].size = size;
	 ht[i].edata = NULL;
	 ht[i].now = 0; //no need lock
	 ht[i].mask = size - 1;
	 pthread_mutex_init(&(ht[i].lock),NULL);
	 if((ht[i].table = malloc(sizeof(struct hdata) * ht[i].size))== NULL)
		{
		 for(j = 0;j < i;j ++)
			 free(ht[j].table);
		 free(ht);
		 return NULL;
		}
	 for(j = 0;j < size;j ++)
		{
		 ht[i].table[j].list = NULL;	
		 pthread_mutex_init(&(ht[i].table[j].lock),NULL);
		}
	}
 return ht;
}


int htable_find_io(struct htable *ht,int idx,int off,uchar *buffer,uchar *key,int vlen)
{
 int ret,debug = DEBUG_TIMES;
 struct hdata *hd = NULL;
 struct hentry *he = NULL;
 if(idx > HASH_TABLE_SIZE)
	return -1;
 hd = ht->table + idx;
 pthread_mutex_lock(&hd->lock);
 if(hd->list == NULL)
	{
	 pthread_mutex_unlock(&hd->lock);
	 return -1;
	}
 he = hd->list;
 if(off == 0 && he != NULL)
	{
	 ret = deep_copy(he->val,buffer,vlen);
	 memcpy(key,he->key,strlen(he->key) + 1);
	 pthread_mutex_unlock(&hd->lock);
	 return ret;
	}
 while(he != NULL)
	{
	 he = he->next;
	 off --;
	 if(off == 0 && he != NULL)
		{
		 ret = deep_copy(he->val,buffer,vlen);
		 memcpy(key,he->key,strlen(he->key) + 1); //type,domain.0
		 pthread_mutex_unlock(&hd->lock);
		 return ret;
		}
	 debug --;
	 if(debug == 0)
		{
		 printf("error in storage...\n");
		 exit(0);
		}
	}
 pthread_mutex_unlock(&hd->lock);
 return -1;
}


int htable_find(struct htable *ht,uchar *key,uchar *buffer,int vlen,struct mvalue *md)
{
 int idx,debug = DEBUG_TIMES,ret;
 struct hdata *hd = NULL;
 struct hentry *he = NULL;
 struct mvalue *mx = NULL;
 hashval_t h = (ht->h)(key);
 idx = h & ht->mask;
 hd = ht->table + idx;
 pthread_mutex_lock(&hd->lock);
 if(hd->list == NULL)
	{
	 pthread_mutex_unlock(&hd->lock);
	 return -1;
	}
 he = hd->list;
 while(he != NULL)
	{
	 if((ht->c)(key,he->key) == 0)
		{
		 if(buffer != NULL)
			ret = deep_copy(he->val,buffer,vlen);
		 else
			{
			 if(md != NULL)
				{
				 mx = (struct mvalue*)(he->val);
				 *md = *mx; //meta data
				}
			 ret = 1;//successed
			}
		 pthread_mutex_unlock(&hd->lock);
		 return ret;
		}
	 he = he->next;
	 if(debug -- == 0)
		{
		 printf("error in htable find\n");
		 exit(0);
		}
	}
 pthread_mutex_unlock(&hd->lock);
 return -1;
}


struct hentry* htable_delete(struct htable *ht,uchar *key)
{
 hashval_t h = (ht->h)(key);
 int idx = h & ht->mask,debug = DEBUG_TIMES;
 struct hdata *hd = NULL;
 struct hentry *he = NULL,*prev = NULL;
 hd = ht->table + idx;
 pthread_mutex_lock(&hd->lock);
 if(hd->list == NULL)
	{
	 pthread_mutex_unlock(&hd->lock);
	 return NULL;
	}
 he = hd->list;
 if((ht->c)(key,he->key) == 0)
	{
	 hd->list = he->next;
	 pthread_mutex_unlock(&hd->lock);
	 pthread_mutex_lock(&ht->lock);
	 ht->now --;
	 pthread_mutex_unlock(&ht->lock);
	 return he;
	}
 prev = he;
 he = he->next;
 while(he != NULL)
	{
	 if((ht->c)(key,he->key) == 0)
		{
		 prev->next = he->next;
		 pthread_mutex_unlock(&hd->lock);
		 pthread_mutex_lock(&ht->lock);
		 ht->now --;
		 pthread_mutex_unlock(&ht->lock);
		 return he;
		}
	 prev = he;
	 he = he->next;
	 debug --;
	 if(debug == 0)
		{
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
int htable_insert(struct htable *ht,uchar *key,uchar *val,int replace,struct mvalue *mv)
{
 hashval_t hash;
 int idx,ret,debug = DEBUG_TIMES;
 struct hentry *he = NULL,*cl = NULL;
 struct hdata *hd = NULL;
 struct mvalue *pt = NULL;//protect root and gtld
 uchar dlen = strlen(key) + 1;
 he = malloc(sizeof(struct hentry) + dlen);
 if(he == NULL)
	{
	 printf("oom\n");
	 return -1;
	}
 he->next = NULL;
 he->val = val;
 memcpy(he->key,key,dlen);
 hash = ht->h(key);
 idx = hash & ht->mask;
 //printf("hash %u,idx is %d\n",hash,idx);
 hd = ht->table + idx;
 pthread_mutex_lock(&hd->lock);
 if(hd->list == NULL)
	hd->list = he;
 else
	{
	 cl = hd->list;
	 while(cl != NULL)
		{
		 if((ht->c)(cl->key,he->key) == 0) //the exactly same elements
			{
			 if(replace == 1)
				{
				 if(mv != NULL) //get old meta data
					*mv = *(struct mvalue*)(cl->val);
				 if((mv != NULL) && (mv->ttl != (MAX_TTL + 1)))
					{
					 free(cl->val); //old value
					 cl->val = he->val;
					 ret = 1;
					}
				 else //never replace (MAX_TTL + 1) records
					{
					 //free(he->val);
					 he->val = NULL;
					 ret = 2;
					}
				}
			 else
				 ret = -1; //drop
			 pthread_mutex_unlock(&hd->lock);
			 free(he);
			 return ret; //replace
			}
		 cl = cl->next;
		 debug --;
		 if(debug == 0)
			{
			 printf("error in storage2\n");
			 exit(0);
			}
		}
	 he->next = hd->list;
	 hd->list = he;
	}
 pthread_mutex_unlock(&hd->lock);
 pthread_mutex_lock(&ht->lock);
 ht->now ++;
 pthread_mutex_unlock(&ht->lock);
 return 0;
}


int find_record_with_ttl(struct htable *ht,uchar *key,uchar *val,int vlen,struct mvalue *md)
{
 int idx,ret;
 idx = get_pre_mem_hash(key);
 ret = htable_find(ht + idx,key,val,vlen,md);
 if(ret > 0)
	{
	 if(ttl_expired(val) == 1)
		 htable_delete(ht + idx,key);
	 else
		 return ret;
	}
 return -1;
}


/////////////////////////////////////////////////////////////////
////////////////////////////////dbg//////////////////////////////
#define THREADX (5)
#define NUMX (10000)
struct st_hlp
{
 struct htable *ht;
 int idx;
};


void* st_th(void *arg)
{
 int i,idx;
 uchar key[50] = {0};
 uchar *val = NULL;
 int pre = 0;
 struct hentry *he = NULL;
 struct htable *ht;
 struct st_hlp *sh = (struct st_hlp*)arg;
 idx = sh->idx;
 ht = sh->ht;
 for(i = idx * NUMX;i < (idx + 1) * NUMX;i ++)
	{
	 sprintf(key,"%dkey",i);
	 val = malloc(50);
	 sprintf(val,"%dval",i);
	 //printf("%d,%s,%s\n",idx,key,val);
	 pre = get_pre_mem_hash(key);
	 htable_insert(ht + pre,key,val,0,NULL);
	}
 if(idx == (THREADX - 1))
	idx = -1;
 sleep(2);
 for(i = (idx + 1) * NUMX;i < (idx + 2) * NUMX;i ++)
	{
	 sprintf(key,"%dkey",i);
	 pre = get_pre_mem_hash(key);
	 he = htable_delete(ht + pre,key);
	 if(he == NULL)
		{
		 printf("error in test %s,%d,%d\n",key,idx,i);
		}
	 else
		{
		 //printf("right in %d,%s,%s\n",idx,he->key,he->val);
		 free(he->val);
		 free(he);
		}
	}
 sleep(5);
 return NULL;
}


int storage_test(void)
{
 struct htable *ht;
 pthread_t pt[THREADX];
 int i;
 struct st_hlp sh[THREADX];
 //ht = htable_create(NULL,dict_comp_str_equ,HASH_TABLE_SIZE,MULTI_HASH);
 if(ht == NULL)
	dns_error(0,"create htable error");
 for(i = 0;i < THREADX;i ++)
	{
	 sh[i].ht = ht;
	 sh[i].idx = i;
	 if(pthread_create(pt + i,NULL,st_th,sh + i))
		dns_error(0,"create pthread");
	}
 for(i = 0;i < THREADX;i ++)
	pthread_join(pt[i],NULL);
 sleep(2);
 return 0;
}
