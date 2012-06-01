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


#include "utils.h"


int slog(uchar *msg,int fd,pthread_mutex_t *lock)
{
 return 0;
}


//get random things
int get_random_data(uchar *buffer,int len)
{
 int fd = -1;
 if((buffer == NULL) || (len < 0))
	return -1;
 fd = open("/dev/urandom",O_RDONLY);
 if(fd <= 0)
	 return fd;
 read(fd,buffer,len);
 close(fd);
 return 0;
}


//get a c string
//little function,will be replaced by mm sonn.
//-----------------------begin-----------------//
uchar* get_str(uchar *str,int len)
{
 uchar *ret = malloc(len + 1);
 strncpy(ret,str,len + 1);
 ret[len] = 0;
 return ret;
}


//free it
void put_str(uchar *str)
{
 free((void*)str);
}
//----------------------end---------------------//


//signal handler,be enhenced soon.
//---------------------system func begin---------------//
static void sig_segment_fault(int signo)
{
 printf("sig number is %d\n",signo);
 exit(0);
}


//spider and author and
//main thread may have
//different handlers
int trig_signals(int sig)
{
 sigset_t bset,oset;
 int sigs[] = {SIGINT,SIGBUS,SIGSEGV,SIGPIPE,},i,sig_num;
 struct sigaction sa,oa;
 bzero(&sa,sizeof(sa));
 sa.sa_handler = sig_segment_fault;
 sa.sa_flags = SA_RESTART;
 for(i = 0;i < sizeof(sigs) / sizeof(sigs[0]);i ++)
	{
	 sig_num = sigs[i];
	 sigaction(sig_num,&sa,&oa);
	}
 sigemptyset(&bset);
 sigaddset(&bset,SIGUSR1); 
 if(pthread_sigmask(SIG_BLOCK,&bset,&oset) != 0)
	dns_error(0,"sig error");
 return 0;
}


void drop_privilege(uchar *root)
{
 if(root == NULL)
	return;
 //chroot(root);
}
//------------------system func end--------------------------//


//for dict
//-------------------compare func begin---------------------//
int dict_comp_uint_equ(void *a,void *b)
{
 uint *u1 = a;
 uint *u2 = b;
 if(u1 == NULL)
	return -1;
 if(u2 == NULL)
	return 1;
 if(*u1 == *u2)
	return 0;
 return u1 > u2 ? 1 : -1;
}


int dict_comp_str_equ(void *a,void *b)
{
 uchar *d1 = a;
 uchar *d2 = b;
 int to = 256;
 if(d1 == NULL)
	return -1;
 if(d2 == NULL)
	return 1;
 while(*d1 != 0 && *d2 != 0)
	{
	 if(*d1 > *d2)
		return 1;
	 if(*d1 < *d2)
		return -1;
	 d1 ++;
	 d2 ++;
	 if(to -- == 0) //maybe an invalid string
		{
		 printf("str compare error\n");
		 exit(0);
		}
	}
 if(*d1 == 0 && *d2 == 0)
	return 0;
 if(*d1 == 0)
	return -1;
 return 1;
}


//if elems put in the same time
//the one who has bigger idx will be bigger.
int rbt_comp_ttl_gt(void *v1,void *v2,void *argv)
{
 int ret;
 //argv not used
 struct ttlnode *n1,*n2;
 //if v1=v2=null. v1 > v2 by default.
 if(v2 == NULL)
	return 1;
 if(v1 == NULL)//v1 is null,v2 not null.
	return -1;
 n1 = (struct ttlnode*)v1;
 n2 = (struct ttlnode*)v2;
 if(n1->exp > n2->exp)
	return 1;
 if(n1->exp < n2->exp)
	return -1;
 ret = strcmp(n1->data,n2->data);
 if(ret > 0)
	return 1;
 if(ret < 0)
	return -1;
 return 0;
}


int rbt_comp_uint_gt(void *v1,void *v2,void *argv)
{
 //argv not used
 uint n1,n2;
 //if v1=v2=null. v1 > v2 by default.
 if(v2 == NULL)
	return 1;
 if(v1 == NULL)//v1 is null,v2 not null.
	return -1;
 n1 = *(uint*)v1;
 n2 = *(uint*)v2;
 if(n1 == n2)
	return 0;
 return n1 > n2 ? 1 : -1;
}
//-----------------compare func end---------------------//


//str functions,no error check,no test
//-----------------------str begin----------------------//
int to_lowercase(uchar *msg,int len)
{
 int i; 
 for(i = 0;i < len;i ++)
	if(msg[i] >= 'A' && msg[i] <= 'Z')
		msg[i] = msg[i] + 'a' - 'A';
 return 0;
}


int to_uppercase(uchar *buf,int n)
{
 int i;
 for(i = 0;i < n;i ++)
	{
	 if(buf[i] >= 'a' && buf[i] <= 'z')
		buf[i] = buf[i] + 'A' - 'a';
	}
 return 0;
}


int str_to_uchar4(const char *addr,uchar *val)
{
 uint v = 0,tv[4] = {0},idx = 0;
 int i,n = strlen(addr);
 for(i = 0;i < n;i ++)
	{
	 if(addr[i] >= '0' && addr[i] <= '9')
		tv[idx] = tv[idx] * 10 + addr[i] - '0';
	 else
		{
		 idx ++;
		 if(addr[i] != '.' || idx == 4) //format error
			{
			 *val = 0;
			 return -1;
			}
		}		
	}
 for(i = 0;i < 4;i ++)
	 val[i] = tv[i];
 return 0;
}


int str_to_uchar6(uchar *addr,uchar *val)
{
 ushort tv[8] = {0};
 int idx = 0,gap = 0,gapidx = -1,hasgap = 0;
 int i,n = strlen(addr);
 char tmp;
 to_lowercase(addr,n);
 memset(val,0,16);
 for(i = 0;i < n;i ++)
	{
	 tmp = addr[i];
	 if(tmp >= '0' && tmp <= '9')
		{
		 gap = 0;
		 tv[idx] = tv[idx] * 16 + tmp - '0';
		}
	 else if(tmp >= 'a' && tmp <= 'z')
		{
		 gap = 0;
		 tv[idx] = tv[idx] * 16 + tmp - 'a' + 10;
		}
	 else
		{
		 idx ++;
		 if(gap == 1)
			{
			 if(hasgap == 1) //format error
				 return -1;
			 hasgap = 1;
			 gapidx = idx - 1;
			}
		 if(gap == 0)
		 	gap = 1;
		 if(tmp != ':' || idx == 8)
			{
			 val[0] = val[1] = val[2] = val[3] = 0;
			 return 0;
			}
		}
	}
 if(hasgap == 1) //we have an gap
	{
	 for(i = 0;i < gapidx;i ++)
		{
		 val[i * 2] = tv[i] / 256;
		 val[i * 2 + 1] = tv[i] % 256;
		}
	 for(i = idx - 1;i >= gapidx;i --)
		{
		 val[(i + 7 - idx + 1) * 2] = tv[i + 1] / 256;
		 val[(i + 7 - idx + 1) * 2 + 1] = tv[i + 1] % 256;
		}
	}
 else
	{
	 for(i = 0;i < 8;i ++)
		{
		 val[i * 2] = tv[i] / 256;
		 val[i * 2 + 1] = tv[i] % 256;
		}
	}
 return 0;
}


int fix_tail(char *domain)
{
 int len = strlen(domain);
 char c;
 len --;
 c = domain[len];
 if(c == '\r' || c == '\n')
	{
	 domain[len] = 0;
	 len --;
	}
 c = domain[len];
 if(c == '\r' || c == '\n')
	{
	 domain[len] = 0;
	 len --;
	}
 return 0;
}
//-------------------str end--------------------------//


//offset [0,15]
//tested by rbtree_test() in datas.c.
//-------------------bit functions begin--------
int opr_bit(unsigned short *bit,int off,int set)
{
 unsigned short mask = 1;
 if(off > 15 || off < 0)
	return -1;
 mask <<= off;
 if(set == 0) //clear
	mask = ~mask;
 if(set == 0)
	*bit = *bit & mask;
 else
	 *bit = *bit | mask;
 return 0;
}


int set_bit(unsigned short *bit,int off)
{
 opr_bit(bit,off,1);
 return 0;
}


int clr_bit(unsigned short *bit,int off)
{
 opr_bit(bit,off,0);
 return 0;
}

int tst_bit(const unsigned short bit,int off)
{
 unsigned short mask = 1;
 if(off > 15 || off < 0)
	return -1;
 mask <<= off;
 if((bit & mask) == 0)
	return 0;
 return 1;
}
//----------------bit functions end---------------------


//multi threads safe
//test by rbtree_test() in datas.c
int get_time_usage(struct timeval *tv,int start)
{
 ulong msec = 0;
 struct timeval tmp;
 if(tv == NULL)
	return -1;
 if(start == 1)//start
	 gettimeofday(tv,NULL);
 else //end
	{
	 tmp = *tv;
	 gettimeofday(tv,NULL);
	 if(tv->tv_usec < tmp.tv_usec)
		{
		 msec = (tv->tv_usec - tmp.tv_usec + 1000000) / 1000;
		 tv->tv_sec --;
		}
	 printf("%lu s,%lu ms\n",tv->tv_sec - tmp.tv_sec,msec);
	}
 return 0;
}


//------------trivial function begin---------------------------
//for debug


int is_uppercase(int c)
{
 if(c >= 'A' && c <= 'Z')
	return 1;
 return 0;
}


int is_lowercase(int c)
{
 if(c >= 'a' && c <= 'z')
	return 1;
 return 0;
}


int empty_function(int i)
{
 int j;
 j = i;
 return 0;
}


void insert_mem_bar(void)
{
 int i,size = random() % 99 + 10000;
 uchar *ptr = malloc(size);
 if(ptr == NULL)
	return;
 for(i = 0;i< size;i ++)
	ptr[i] = i;
 free(ptr);
}


int test_lock(pthread_mutex_t *l)
{
 if(pthread_mutex_trylock(l) < 0)
	 return -1;
 pthread_mutex_unlock(l);
 return 0;
}
//------------trivial function end------------------------------


//-------------------debug print begin-------------------------
void dbg_print_bit(unsigned short bit)
{
 int i;
 unsigned short val = 1 << 15;
 for(i = 0;i < 16;i ++)
	{
	 if((bit & val) == 0)
		printf("0");
	 else
		printf("1");
	 if(((i + 1) % 4) == 0 && (i != 15))
		printf(",");
	 val = val >> 1;
	}
 printf("\n");
}


void print_hex(uchar *val,int n)
{
 int i;
 for(i = 0;i < n;i ++)
	printf("%x,",val[i]);
 printf("\n");
}


//global error function
void dns_error(int level,char *msg)
{
 dbg("Error:%s\n",msg);
 fflush(stdout);
 if(level == 0)
	 exit(-1);
}


//output debug infomartion
int dbg(const char *format, ...)
{
 int ret;
 va_list ap;
 va_start(ap,format);
 printf("dbg:");
 ret = vprintf(format,ap);
 va_end(ap);
 return ret;
}
//-----------------------debug print end--------------------


hashval_t uint_hash_function(void *ptr)
{
 uint key = *(uint*)ptr;
 key += ~(key << 15);
 key ^= (key >> 10);
 key += (key << 3);
 key ^= (key >> 6);
 key += ~(key << 11);
 key ^= (key >> 16);
 return key;
}


hashval_t nocase_char_hash_function(void *argv)
{
 int len = strlen(argv);
 uchar *buf = argv;
 hashval_t hash = 5381;
 to_lowercase(buf,len);
 while(len --)
	hash = (((hash << 5 )+ hash) + *buf++);
 return hash;
}
