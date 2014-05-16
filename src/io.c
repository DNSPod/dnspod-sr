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
#include "config.h"

//standard format support only
//name,ttl,type,data


extern int add_query_info(int log_type, int idx, uint16_t type);

uchar *
jump_space(uchar * itor)
{
    //close current string and jump to begin of next string
    int t = 100;
    while (itor[0] != ' ' && itor[0] != '\t' && t--)
        itor++;
    itor[0] = 0;                // close the string.
    itor++;
    while (itor[0] == ' ' || itor[0] == '\t') {
        itor++;
        if (t-- == 0) {
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
int
read_records_from_file(const char * fn, struct htable *ds,
                       struct rbtree *rbt, int hijack)
{
    FILE *fd = NULL;
    uchar vbuffer[5000] = { 0 }, ipv4[4], ipv6[16];
    uchar rbuffer[1024] = { 0 };
    uchar tmpdomain[256] = ".", tmptype[10] = "NS";
    uchar *ps[5] = { 0 };
    uchar *ritor = NULL;
    uchar *vitor = vbuffer;
    int tmplen = 0, type = 0, i/*, seg = 0*/;
    uchar *kbuffer;//[256] = { 0 };
    uint ttl = 0, tmpttl = 0;
    int dlen;
    struct mvalue *mv = (struct mvalue *) vbuffer;
    //uint vallen = sizeof(struct mvalue);
    packet_type lowerdomain, lowerns;
    
    if (ds == NULL)
        dns_error(0, "datasets null");
    if ((fd = fopen(fn, "r")) == NULL) {
        fprintf(stderr, "open file %s error\n", fn);
        perror("fopen");
        dns_error(0, "open file root.z");
    }
    kbuffer = lowerdomain.domain;
    mv->num = 0;
    mv->ttl = 0;
    mv->len = 0;
    mv->seg = 0;
    vitor = vbuffer + sizeof(struct mvalue);

    while (fgets((char *)rbuffer, 1024, fd) != NULL) {
        ritor = rbuffer;
        ps[0] = ritor;
        for (i = 1; i < 5; i++) {
            ritor = jump_space(ritor);
            ps[i] = ritor;
        }
        to_lowercase(ps[0], strlen((const char *)ps[0]) + 1);
        fix_tail((char *)ps[4]);        //drop the \n and \r
        tmpttl = atoi((const char *)ps[1]);
        ttl = tmpttl + global_now;      // 600 + now
        if (tmpttl >= MAX_TTL + 1)      // > max + 1,already added now
            ttl = tmpttl;       // == max + 1,never expired
        if (tmpttl == NEVER_EXPIRED1)   //special value in root.z, never expired.
            ttl = MAX_TTL + 1;
        if (tmpttl == NEVER_EXPIRED2)
            ttl = MAX_TTL + 1;
        if ((strcmp((const char *)ps[0], (const char *)tmpdomain) != 0)
            || (strcmp((const char *)ps[3], (const char *)tmptype) != 0)) {
            if (strcmp((const char *)tmptype, "NS") == 0)
                type = NS;
            else if (strcmp((const char *)tmptype, "A") == 0)
                type = A;
            else if (strcmp((const char *)tmptype, "AAAA") == 0)
                type = AAAA;
            if (strcmp((const char *)tmptype, "CNAME") == 0)
                type = CNAME;
            dlen = strlen((const char *)tmpdomain) + 1;
            if (dlen > 1) {
                str_to_len_label(tmpdomain, dlen);
//                 make_type_domain((uchar *)tmpdomain, dlen, type,
//                         kbuffer);
//                 memcpy(kbuffer, tmpdomain, dlen);
                check_dns_name(tmpdomain, &lowerdomain);
                insert_kv_mem(rbt, ds, kbuffer, dlen, type, vbuffer, 
                              mv->len + sizeof(struct mvalue), hijack, &lowerdomain); //key value
            }
            memcpy(tmptype, ps[3], strlen((const char *)ps[3]) + 1);
            memcpy(tmpdomain, ps[0], strlen((const char *)ps[0]) + 1);
            vitor = vbuffer + sizeof(struct mvalue);
            mv->num = 0;
            mv->ttl = 0;
            mv->len = 0;
            mv->seg = 0;
        }
        if (ttl > mv->ttl)
            mv->ttl = ttl;
        if (strcmp((const char *)ps[3], "NS") == 0 || strcmp((const char *)ps[3], "CNAME") == 0) {
//             to_lowercase((uchar *)ps[4], strlen(ps[4]) + 1);
            str_to_len_label(ps[4], strlen((const char *)ps[4]) + 1);
            tmplen = check_dns_name(ps[4], &lowerns);
            if (tmplen > 0) {
                memcpy(vitor, lowerns.domain, tmplen);
                vitor += tmplen;
                mv->len += tmplen;
                mv->num++;
            }
        } else if (strcmp((const char *)ps[3], "A") == 0) {
            str_to_uchar4((const char *)ps[4], ipv4);
            memcpy(vitor, ipv4, 4);
            vitor += 4;
            mv->len += 4;
            mv->num++;
        } else if (strcmp((const char *)ps[3], "AAAA") == 0) {
            str_to_uchar6(ps[4], ipv6);
            memcpy(vitor, ipv6, 16);
            vitor += 16;
            mv->len += 16;
            mv->num++;
        }
        //else
        //printf("error type %s\n",ps[3]);
    }
    if (strcmp((const char *)tmptype, "NS") == 0)
        type = NS;
    if (strcmp((const char *)tmptype, "A") == 0)
        type = A;
    if (strcmp((const char *)tmptype, "AAAA") == 0)
        type = AAAA;
    dlen = strlen((const char *)tmpdomain) + 1;
    if (dlen > 1) {
        str_to_len_label(tmpdomain, dlen);
//         make_type_domain((uchar *)tmpdomain, dlen, type,
//                 kbuffer);
        insert_kv_mem(rbt, ds, kbuffer, dlen, type, vbuffer, 
                      mv->len + sizeof(struct mvalue), hijack, &lowerdomain); //key value
    }
    fclose(fd);
    return 0;
}


int
read_root(struct htable *ds, struct rbtree *rbt)
{
    return read_records_from_file(SR_ROOT_FILE, ds, rbt, 0);
}


int
refresh_records(struct htable *ds, struct rbtree *rbt)
{
    printf("read from records.z\n");
    return read_records_from_file(SR_RECORDS_FILE, ds, rbt, 1);
}


int
create_transfer_point(uchar * name, struct htable *fwd, int n)
{
    int i = -1, dlen, ret;
    uchar ipv4[4] = { 0 }, *addr = NULL, *itor;
//     uchar kbuffer[256] = { 0 };
    uchar vbuffer[1000] = { 0 };
    uchar *v = NULL;
    hashval_t hash = 0;
    dlen = strlen((const char *)name) + 1;
    str_to_len_label(name, dlen);
//     make_type_domain(name, dlen, A, kbuffer);   //forward ip
    addr = name + dlen;
    struct mvalue *mv = (struct mvalue *) vbuffer;
    mv->num = 0;
    mv->ttl = MAX_TTL + 1;
    mv->len = 0;                //not include the struct itself
    itor = vbuffer + sizeof(struct mvalue);
    for (i = 0; i < n; i++) {
        str_to_uchar4((const char *)addr, ipv4);
        memcpy(itor, ipv4, 4);
        addr = addr + strlen((const char *)addr) + 1;
        itor += 4;
        mv->len += 4;
        mv->num++;
        if (addr[0] == 0)
            break;
    }
    v = malloc(mv->len + sizeof(struct mvalue));
    memcpy(v, vbuffer, mv->len + sizeof(struct mvalue));
    ret = htable_insert(fwd, name, dlen, A, v, 0, NULL, &hash);
    assert(ret >= 0);
    return 0;
}


int read_resolve(FILE * fd, char **nameservers, int n)
{
    char buf[1024] = {0}, *tmp = NULL;
    int i = 0;
    char placeholder[128] = {0};
    char temp[32] = {0};
    if (fd == NULL || n <= 0) {
        return -1;
    }
    i = 0;

    while (fgets(buf, 1024, fd) != NULL) {
        fix_tail(buf);
        if (buf[0] == ':') {
            break;
        }
        tmp = strstr(buf, "nameserver");
        if (!tmp) {
            continue;
        }
        if (i + 1 > n) {
            continue;
        }
        memset(placeholder, 0, 128);
        memset(temp, 0, 32);
        sscanf(buf, "%s %s", placeholder, temp);
        // 255.255.255.255 15
        // 1.1.1.1 7
        if (strlen(temp) > 15 || strlen(temp) < 7) {
            continue;
        }
        nameservers[i++] = strdup(temp);
    }
    return i;
}

int
read_logpath(FILE * fd, char * path)
{
    if (fgets(path, 512, fd) == NULL)
        memcpy(path, "/var/dnspod-sr/log/", 20);  // if open failed, set ./ again
    fix_tail(path);
    if (mkdir(path, 0755) != 0) {
        if (errno == EEXIST) {
            return 0;
        } else {
            dns_error(0, "create log parent dir failed");
        }
    }

    return 0;
}


int
read_transfer(FILE * fd, struct htable *fwd)
{
    char buf[1024] = { 0 }, *tmp = NULL;
    int i, n;
    if (fd == NULL || fwd == NULL)
        return -1;
    while (fgets(buf, 1024, fd) != NULL) {
        fix_tail(buf);
        if (buf[0] == ':')
            break;              //end
        tmp = strstr(buf, ":");
        if (tmp != NULL) {
            tmp[0] = 0;         // drop :
            tmp++;
            n = 1;
            for (i = 0; i < 8; i++) {
                tmp = strstr(tmp, ",");
                if (tmp == NULL)
                    break;
                else {
                    n++;
                    tmp[0] = 0; //drop ,
                    tmp++;
                }
            }
            if (i != 8)         //too more ips
                create_transfer_point((uchar *)buf, fwd, n);
        }
    }
    return 0;
}


int
read_config(const char *fn, char * logpath, struct htable *forward, char **nameservers)
{
    FILE *fd = NULL;
    char buf[1024] = {0};
    if (fn == NULL) {
        return -1;
    }
    if ((fd = fopen(fn, "r")) == NULL) {
        return -1;
    }
    while (fgets(buf, 1024, fd) != NULL) {
        fix_tail(buf);
        if (strcmp(buf, "xfer:") == 0) {
            read_transfer(fd, forward);
            continue;
        }
        if (strcmp(buf, "log_path:") == 0) {
            read_logpath(fd, logpath);
            continue;
        }
        if (strcmp(buf, "resolve:") == 0) {
            read_resolve(fd, nameservers, 2);
            continue;
        }
    }
    fclose(fd);
    return 0;
}


int
fill_domain_to_len_label(const char *from, char *to)
{
    int len = 0;
    const char *itor = from;
    if (itor[0] == 0) {
        to[0] = '.';
        return 1;
    }
    while (itor[0] != 0) {
        memcpy(to, itor + 1, itor[0]);
        to += itor[0];
        len += itor[0];
        itor = itor + itor[0] + 1;
        to[0] = '.';
        to++;
        len++;
    }
    return len;
}


//domain, query domain
//type, query type
//addr, client addr
int
write_loginfo_into_file(struct log_info *log, const uchar * domain, int dlen, int type,
                        struct sockaddr_in *addr)
{
    /* char buffer[600] = { 0 }; */
    /* char *itor; */
    uchar tp = type % 256;
    /* itor = buffer; */
    int fd = log->logfd;
    int tmplen = 0;
    int ret = 0;
    if (fd <= 0)
        return -1;
    if (domain != NULL) {
        tmplen = 8 + dlen;
        if (log->log_cache_cursor + tmplen >= LOG_CACHE_SIZE) {
            ret = write(log->logfd, log->log_cache, log->log_cache_cursor);
            if (ret == -1) {
                perror("write");
            }
            log->log_cache_cursor = 0;
        }
        if (tmplen >= LOG_CACHE_SIZE) {
            return 0;
        } else {
            log->log_cache[log->log_cache_cursor] = 255;
            log->log_cache[log->log_cache_cursor + 1] = tp;
            log->log_cache[log->log_cache_cursor + 2] = 2; /* default label_start_num: 2 */
            memcpy(log->log_cache + log->log_cache_cursor + 3,
                    &(addr->sin_addr.s_addr), sizeof(addr->sin_addr.s_addr));
            memcpy(log->log_cache + log->log_cache_cursor + 3 + sizeof(addr->sin_addr.s_addr),
                    domain, dlen);
            log->log_cache_cursor = log->log_cache_cursor + tmplen;
            log->log_cache[log->log_cache_cursor - 1] = '#';
        }


        /*
         * len = fill_domain_to_len_label((const char *)domain, itor);
         * itor += len;
         * memcpy(itor, &tp, sizeof(uchar));
         * itor += sizeof(uchar);
         * if (addr != NULL) {
         *     //127.0.0.1 would be 0x 7f 00 00 01
         *     memcpy(itor, &(addr->sin_addr.s_addr), sizeof(ulong));
         *     itor += sizeof(struct in_addr);
         * }
         * write(fd, buffer, itor - buffer);
         */
    }
    /* write(fd, "\n", 2); */
    return 0;
}


//0001111111.log
//1221111111.log
//first bit 0 or 1 means fetcher or quizzer
//second and third bits means idx
//last bits means time
int
create_new_log(uchar * prefix, int idx, int type)
{
    static char pf[50] = { 0 };
    char filename[80] = { 0 };
    char final[130] = { 0 };
    int fd = -1, bit, len;
    mode_t mode;
    time_t prev;
    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (pf[0] == 0)
        memcpy(pf, prefix, strlen((const char *)prefix) + 1);
    filename[0] = 'f';
    if ((type != TYPE_QUIZZER) && (type != TYPE_FETCHER))
        return -1;
    if (type == TYPE_QUIZZER)
        filename[0] = 'q';
    bit = idx / 100;
    filename[1] = bit + '0';
    bit = (idx % 100) / 10;
    filename[2] = bit + '0';
    bit = idx % 10;
    filename[3] = bit + '0';
    prev = global_now - (global_now % LOG_INTERVAL);
    sprintf(filename + 4, "%lu", prev);
    memcpy(filename + strlen(filename), ".log", 5);
    len = strlen(pf);
    memcpy(final, pf, len);
    memcpy(final + len, filename, strlen(filename) + 1);
    fd = open(final, O_WRONLY | O_CREAT, mode);
    return fd;
}


//fetcher
//1.TIME#
//0.name.type.clientip#
//add speed/flow info to the shared mem, in order to looked up by other process
int
write_log(struct log_info *log, int idx, const uchar * domain, int dlen, 
          int type, struct sockaddr_in *addr)
{
    add_query_info(log->log_type, idx, type);
    int lfd = log->logfd;
    if (((global_now % LOG_INTERVAL) == 0) && (global_now > (log->lastlog))) {
        close(lfd);
        lfd = create_new_log(NULL, idx, log->log_type);
        log->logfd = lfd;
    }
    write_loginfo_into_file(log, domain, dlen, type, addr);
    log->lastlog = global_now;
    return 0;
}
