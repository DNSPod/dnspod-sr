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


#include "io.h"

//standard format support only
//name,ttl,type,data


static uchar* jump_space(uchar *itor)
{
 //close current string and jump to begin of next string
 int t = 100;
 while(itor[0] != ' ' && itor[0] != '\t' && t --)
	itor ++; 
 itor[0] = 0; // close the string.
 itor ++;
 while(itor[0] == ' ' || itor[0] == '\t')
	{
	 itor ++;
	 if(t -- == 0)
		{
	 	 printf("error line in file\n");
		 return NULL;
		}
	}
 return itor;
}


//ftp://ftp.internic.net/domain/root.zone
//support type
//A,
//NS,
//CNAME,
//SOA,
//MX,
//TXT,
//AAAA,
//SRV
int read_records_from_file(const uchar *fn,struct htable *ds,struct rbtree *rbt)
{
 FILE *fd = NULL;
 uchar vbuffer[5000] = {0},ipv4[4],ipv6[16];
 uchar rbuffer[1024] = {0};
 uchar tmpdomain[256] = ".",tmptype[10] = "NS";
 uchar *ps[5] = {0},*vitor = vbuffer;
 uchar *ritor = NULL;
 int tmplen = 0,type = 0,i,seg = 0;
 uchar kbuffer[256] = {0};
 uint ttl = 0,tmpttl = 0;
 struct mvalue *mv = (struct mvalue*)vbuffer;
 //uint vallen = sizeof(struct mvalue);
 if(ds == NULL)
	dns_error(0,"datasets null");
 if((fd = fopen(fn,"r")) == NULL)
	dns_error(0,"open file root.z");
 mv->num = 0;
 mv->ttl = 0;
 mv->len = 0;
 mv->seg = 0;
 vitor = vbuffer + sizeof(struct mvalue);

 while(fgets(rbuffer,1024,fd) != NULL)
	{
	 ritor = rbuffer;
	 ps[0] = ritor;
	 for(i = 1;i < 5;i ++)
		{
		 ritor = jump_space(ritor);
		 ps[i] = ritor;
		}
	 fix_tail(ps[4]); //drop the \n and \r
	 tmpttl = atoi(ps[1]);
	 ttl = tmpttl + global_now; // 600 + now
	 if(tmpttl >= MAX_TTL + 1) // > max + 1,already added now
		ttl = tmpttl; // == max + 1,never expired
	 if(tmpttl == NEVER_EXPIRED1) //special value in root.z, never expired.
		ttl = MAX_TTL + 1;
	 if(tmpttl == NEVER_EXPIRED2)
		ttl = MAX_TTL + 1;
	 if((strcmp(ps[0],tmpdomain) != 0) || (strcmp(ps[3],tmptype) != 0))
		{
		 if(strcmp(tmptype,"NS") == 0)
			type = NS;
		 if(strcmp(tmptype,"A") == 0)
			type = A;
		 if(strcmp(tmptype,"AAAA") == 0)
			type = AAAA;
		 to_lowercase(tmpdomain,strlen(tmpdomain) + 1);
		 str_to_len_label(tmpdomain,strlen(tmpdomain) + 1);
		 make_type_domain(tmpdomain,strlen(tmpdomain) + 1,type,kbuffer);
		 insert_kv_mem(NULL,ds,kbuffer,vbuffer,mv->len + sizeof(struct mvalue)); //key value
		 memcpy(tmptype,ps[3],strlen(ps[3]) + 1);
		 memcpy(tmpdomain,ps[0],strlen(ps[0]) + 1);
		 vitor = vbuffer + sizeof(struct mvalue);
		 mv->num = 0;
		 mv->ttl = 0;
		 mv->len = 0;
		 mv->seg = 0;
		}
	 if(ttl > mv->ttl)
		mv->ttl = ttl;
	 if(strcmp(ps[3],"NS") == 0)
		{
		 to_lowercase(ps[4],strlen(ps[4]) + 1);
		 str_to_len_label(ps[4],strlen(ps[4]) + 1);
		 tmplen = check_dns_name(ps[4],&seg);
		 if(tmplen > 0)
			{
			 memcpy(vitor,ps[4],tmplen);
			 vitor += tmplen;
			 mv->len += tmplen;
			 mv->num ++;
			}
		}
	 else if(strcmp(ps[3],"A") == 0)
		{
		 str_to_uchar4(ps[4],ipv4);
		 memcpy(vitor,ipv4,4);
		 vitor += 4;
		 mv->len += 4;
		 mv->num ++;
		}
 	 else if(strcmp(ps[3],"AAAA") == 0)
		{
		 str_to_uchar6(ps[4],ipv6);
		 memcpy(vitor,ipv6,16);
		 vitor += 16;
		 mv->len += 16;
		 mv->num ++;
		}
 	 //else
		//printf("error type %s\n",ps[3]);
	}
 return 0;
}


int read_root(struct htable *ds,struct rbtree *rbt)
{
 return read_records_from_file("root.z",ds,rbt);
}


int refresh_records(struct htable *ds,struct rbtree *rbt)
{
 printf("read from records.z\n"); 
 return read_records_from_file("records.z",ds,rbt);
}


int create_transfer_point(uchar *name,struct htable *fwd,int n)
{
 int i = -1,dlen;
 uchar ipv4[4] = {0},*addr = NULL,*itor;
 uchar kbuffer[256] = {0};
 uchar vbuffer[1000] = {0};
 uchar *v = NULL;
 dlen = strlen(name);
 str_to_len_label(name,dlen + 1);
 make_type_domain(name,dlen,A,kbuffer); //forward ip
 addr = name + dlen + 1;
 struct mvalue *mv = (struct mvalue*)vbuffer;
 mv->num = 0;
 mv->ttl = MAX_TTL + 1;
 mv->len = 0; //not include the struct itself
 itor = vbuffer + sizeof(struct mvalue);
 for(i = 0;i < n;i ++)
	{
	 str_to_uchar4(addr,ipv4);
	 memcpy(itor,ipv4,4);
	 addr = addr + strlen(addr) + 1;
	 itor += 4;
	 mv->len += 4;
	 mv->num ++;
	 if(addr[0] == 0)
		break;
	}
 v = malloc(mv->len + sizeof(struct mvalue));
 memcpy(v,vbuffer,mv->len + sizeof(struct mvalue));
 htable_insert(fwd,kbuffer,v,0,NULL);
 return 0;
}


int read_logpath(FILE *fd,uchar *path)
{
 if(fgets(path,512,fd) == NULL)
	memcpy(path,"./",3); // if open failed, set ./ again
 fix_tail(path);
 return 0;
}


int read_transfer(FILE *fd,struct htable *fwd)
{
 uchar buf[1024] = {0},*tmp = NULL;
 int idx = 0,i,n;
 if(fd == NULL || fwd == NULL)
	return -1;
 while(fgets(buf,1024,fd) != NULL)
	{
	 fix_tail(buf);
	 if(buf[0] == ':')
		 break; //end
	 tmp = strstr(buf,":");
	 if(tmp != NULL)
		{
		 tmp[0] = 0; // drop :
		 tmp ++;
		 n = 1;
		 for(i = 0;i < 8;i ++)
			{
			 tmp = strstr(tmp,",");
			 if(tmp == NULL)
				break;
			 else
				{
				 n ++;
				 tmp[0] = 0; //drop ,
				 tmp ++;
				}
			}
		 if(i != 8) //too more ips
			 create_transfer_point(buf,fwd,n);
		}
	}
 return 0;
}


int read_config(uchar *logpath,struct htable *forward)
{
 int len,i,n = 0;
 FILE *fd = NULL;
 uchar buf[1024] = {0},*itor = NULL,*tmp = NULL;
 if((fd = fopen("sr.conf","r")) == NULL)
	 return -1;
 while(fgets(buf,1024,fd) != NULL)
	{
	 fix_tail(buf);
	 if(strcmp(buf,"xfer:") == 0)
		{
		 read_transfer(fd,forward);
		 continue;
		}
	 if(strcmp(buf,"log_path:") == 0)
		{
		 read_logpath(fd,logpath);
		 continue;
		}
	}
 fclose(fd);
 return 0;
}


int fill_domain_to_len_label(const char *from,char *to)
{
 int len = 0;
 const char *itor = from;
 if(itor[0] == 0)
	{
	 to[0] = '.';
	 return 1;
	}
 while(itor[0] != 0)
	{
	 memcpy(to,itor + 1,itor[0]);
	 to += itor[0];
	 len += itor[0];
	 itor = itor + itor[0] + 1;
	 to[0] = '.';
	 to ++;
	 len ++;
	}
 return len;
}


//domain, query domain
//type, query type
//addr, client addr
int write_loginfo_into_file(int fd,const uchar *domain,int type,struct sockaddr_in *addr)
{
 int len = 0;
 char buffer[600] = {0};
 char *itor;
 uchar tp = type % 256;
 itor = buffer;
 if(fd <= 0)
	return -1;
 if(domain != NULL)
	{
	 len = fill_domain_to_len_label(domain,itor);
	 itor += len;
	 memcpy(itor,&tp,sizeof(uchar));
	 itor += sizeof(uchar);
	 if(addr != NULL)
		{
		 //127.0.0.1 would be 0x 7f 00 00 01
		 memcpy(itor,&(addr->sin_addr.s_addr),sizeof(ulong));
		 itor += sizeof(struct in_addr);
		}
	 write(fd,buffer,itor - buffer);
	}
 else //write time stamp
	{
	 buffer[0] = '1';// timestamp
	 sprintf(buffer + 1,"%lu",global_now);
	 memcpy(buffer + strlen(buffer),"#",1); //no 0 end
	 write(fd,buffer,strlen(buffer));
	}
 write(fd,"\n",2);
 return 0;
}


//0001111111.log
//1221111111.log
//first bit 0 or 1 means fetcher or quizzer
//second and third bits means idx
//last bits means time
int create_new_log(uchar *prefix,int idx,int type)
{
 static char pf[50] = {0};
 char filename[80] = {0};
 char final[130] = {0};
 int fd = -1,bit,len;
 mode_t mode;
 time_t prev;
 mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
 if(pf[0] == 0)
	memcpy(pf,prefix,strlen(prefix) + 1);
 filename[0] = 'f';
 if((type != TYPE_QUIZZER) && (type != TYPE_FETCHER))
	return -1;
 if(type == TYPE_QUIZZER)
	filename[0] = 'q';
 bit = idx / 100;
 filename[1] = bit + '0';
 bit = (idx % 100) / 10;
 filename[2] = bit + '0';
 bit = idx % 10;
 filename[3] = bit + '0';
 prev = global_now - (global_now % LOG_INTERVAL);
 sprintf(filename + 4,"%lu",prev);
 memcpy(filename + strlen(filename),".log",5);
 len = strlen(pf);
 memcpy(final,pf,len);
 memcpy(final + len,filename,strlen(filename) + 1);
 fd = open(final,O_WRONLY | O_CREAT,mode);
 return fd;
}


//fetcher
//1.TIME#
//0.name.type.clientip#
int write_log(int *fd,time_t *lastlog,int idx,const uchar *domain,int type,struct sockaddr_in *addr)
{
 int lfd = *fd;
 if(((global_now % LOG_INTERVAL) == 0) && (global_now > (*lastlog)))
	{
	 close(lfd);
	 lfd = create_new_log(NULL,idx,TYPE_FETCHER);
	 *fd = lfd;
	}
 write_loginfo_into_file(lfd,domain,type,addr);
 return 0;
}
