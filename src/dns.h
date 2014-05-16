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


#ifndef _DNS_H
#define _DNS_H

#include "storage.h"
#include "net.h"
#include "datas.h"


//-------------SYSTEM LIMIT----------------------
#define MAX_LABEL_LEN (63)
#define MAX_DOMAIN_LEN (255)
#define MIN_MSG_LEN (sizeof(dnsheader) + sizeof(qdns))
//a.b.c.d...15
#define MAX_NS_LVL (16)
#define MAX_UDP_SIZE (512)
//addr to auth.
#define MAX_PAR (7)
#define MAX_RR_NUM (1000)
//query to para_num auth servers
#define PARA_NUM (3)
//-----------------------------------------------



//  header
//  question
//  answer
//  authority
//  additional

//header format
/////////////
//id
//flag(qr:1,opcode:4,aa:1,tc:1,rd:1,ra:1,z:3,rcode:4)
//qdcount
//ancount
//nscount
//arcount
/////////////

//question format
////////////
//name //digit,char,hyphen
//type
//class
////////////

//rr format
////////////
//name
//type
//class
//ttl
//rdlength
//data
////////////


enum {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAIL = 2,
    NAME_ERROR = 3,
    NOT_IMPL = 4,
    REFUSED = 5,
};


enum {
    MAX_TRY_TIMES = 15,
    IP_DATA_LEN = 2000,
};


//0 is q,1 is r
#define QR_Q (0)
#define QR_R (1)
#define GET_QR(flag) ((flag & 0x8000) / 0x8000)
#define SET_QR_R(flag) (flag | 0x8000)
#define SET_QR_Q(flag) (flag & 0x7fff)
#define GET_OPCODE(flag) ((flag & 7800) >> 11)
//we always set opcode 0 at current veserion.
#define QUERY (0)
#define IQUERY (1)
#define STATUS (2)
#define GET_AA(flag) ((flag & 0x0400) / 0x0400)
#define SET_AA(flag) (flag | 0x0400)
#define GET_TC(flag) ((flag & 0x0200) / 0x0200)
#define SET_TC(flag) (flag | 0x0200)
#define GET_RD(flag) ((flag & 0x0100) / 0x0100)
#define SET_RA(flag) (flag | 0x0080)
#define GET_ERROR(flag) (flag & 0x7)
#define SET_ERROR(flag,errcode) (flag & 0xfff0 + errcode)
#define IS_PTR(os) (os >= 0xc000 && os <= 0xcfff)       //in reply msg
#define GET_OFFSET(offset) (offset & 0x3fff)    //the 2 higher bits set to 0
#define SET_OFFSET(offset) (offset | 0xc000)
#define IS_EDNS0(flag) (flag > 0x4000 && flag < 0x4fff)


//only IN support
enum {
    CLASS_IN = 1,
};


struct setheader {
    ushort an;
    ushort ns;
    ushort id;
    ushort dlen;
    uchar *od;
    uchar *itor;
    ushort type;
};



enum {
    AN_SECTION = 2,
    NS_SECTION = 5,
    AR_SECTION = 7,
    DMS_SIZE = 256,
};


struct hlpp {
    int *stype;
    struct htable *ds;
    struct rbtree *rbt;
    uchar *buf;
    int datalen;
    uchar *dms;
    int dmsidx;
    int section;
    uchar *tmpbuf;
    uchar *domainbuf;
    uchar *dmbuf;
};


// enum rrtype {
//     BEGIN_TYPE = 0, A = 1, NS = 2,
//     MD = 3, MF = 4, CNAME = 5, SOA = 6,
//     MB = 7, MG = 8, MR = 9, NUL = 10,
//     WKS = 11, PTR = 12, HINFO = 13,
//     MINFO = 14, MX = 15, TXT = 16, RP = 17,     //rfc1183
//     AFSDB = 18,                 //rfc1183
//                                         /*gap */ SIG = 24, KEY = 25,
//                                         //rfc2065
//     /*gap */ AAAA = 28, /*gap */ NXT = 30,      //rfc2065
//                                 /*gap */ SRV = 33,
//                                 //rfc2782
//     CERT = 37,                  //rfc4398
//     /*gap */ A6 = 38, DNAME = 39, /*rfc2672 *//*gap */ OPT = 41,        //for edns0
//     APL = 42, /*rfc3123 */ DS = 43,     //rfc3658
//                                 /*gap */ RRSIG = 46,
//                                 //rfc4034
//     NSEC = 47, DNSKEY = 48, DHCID = 49, /*rfc4701 *//*gap */ TKEY = 249,
//     /*gap */ AXFR = 252, MAILB = 253,
//     MAILA = 254,                //obsolete
//     ANY = 255,             //*,a request for all records
// };
// 
// //types we support at the moment
// const enum rrtype support_type[] =
//     { A, NS, CNAME, SOA, MX, TXT, AAAA, SRV, PTR };


struct hlpc {
    uchar *name;
    short off, level, ref, mt, len;
};


struct hlpf {
    ushort type;
    ushort len;
    uint ttl;
    uchar *hdr;
    uchar *from;
    uchar *to;
};


#pragma pack (1)
struct fillmsg {
    uint16_t type;
    uint16_t dclass;
    uint32_t ttl;
    uint16_t len;
};
#pragma pack()


#define TYPE_RECORD (7)
#define TYPE_MSG_LINE (1000)
#define TYPE_TCP_MSG (1007)
#define TYPE_UDP_MSG (1009)

#pragma pack (1)
typedef struct tag_dnsheader {
    uint16_t id, flags;
    uint16_t qdcount, ancount, nscount, arcount;
} dnsheader;
#pragma pack ()


#pragma pack (1)
typedef struct tag_dq {
    uint16_t type, dclass;
} qdns;
#pragma pack ()

//some base information about dns msg
struct baseinfo {
    enum rrtype type;
    int err;
    int dlen;
    ushort id;
    packet_type *lowerdomain;
    uchar *origindomain;
};

#pragma pack (1)
struct soa {
    uchar *mname;
    uchar *rname;
    uint32_t serial;            //201102022222, 12334545
    uint32_t refresh, retry, expire, minimum;
};
#pragma pack ()

#pragma pack(1)
//_service._proto.name
//in struct record.data.
//uchar *service
//uchar *proto;
//service and proto are NOT case sensitive.
struct srv {
    uint16_t pri, wei, port;
    //uchar *target;
//name compression is not to be used for this field
};
#pragma pack()


enum {
    MOST_TRY_PER_QUERY = 3,
};


//query from auth server
#define QBUFFER_SIZE (256)
struct qoutinfo {
    //client info
    uchar *td, type;                  //type and domain
    packet_type *lowerdomain;
    struct sockinfo *cli;       //sock info
    ushort cid, dlen, qlen;           //include 0
    ushort lables;
    //query info
    uchar *qing;
    hashval_t *qhash;
    ushort backid;
    ushort aid, mask;           //auth id,domain mask
    ushort qname;               //type
    //status info
    ushort sq;                  //send query flag
    ushort qtimes;              //ns,cname,domain
    ushort socktype, stat;      //this may be diffefrent from client's socktype
    uchar qbuffer[QBUFFER_SIZE];
    hashval_t qbuffer_hash;
    uchar *tdbuffer;
    uchar *tempbuffer;
    uchar *dmbuffer;
    uchar *ipbuffer;
    ushort hascname;
    int tcpfd;
    int tcpnums;
    int mxtry;
    int qns;
    uint64_t stime;
};


enum {
    Q_CNAME = 3,
    Q_DOMAIN = 4,
    Q_NS = 6,
};

int find_addr(struct htable *fwd, struct htable *, mbuf_type *mbuf,
              uchar *, int);


uchar *fill_header_in_msg(struct setheader *);
uchar *fill_rrset_in_msg(struct hlpc *, uchar *, uchar *, int, uchar *);

uint dname_hash(void *);

int check_out_msg(ushort, uchar *, int);
int check_an_msg(ushort, uchar *, int *);
int check_dns_name(uchar * domain, packet_type *lowerdomain);
int check_domain_mask(uchar *, uchar *, int);

int make_dns_msg_for_new(uchar *, ushort, uchar *, int, ushort);
int send_tc_to_client(mbuf_type *mbuf);

uchar *str_to_len_label(uchar * domain, int len);

int get_domain_from_msg(uchar * label, uchar * b, uchar * tmpd, int *tmplen);
int get_dns_info(uchar *, ushort *, ushort *, uint *, ushort *);
int get_level(uchar *);
int make_type_domain(uchar * domain, int dlen, int type, uchar * buffer);
int insert_kv_mem(struct rbtree *, struct htable *ds, uchar * k, int klen, 
                  int type, uchar * v, int vlen, int hijack, packet_type *lowerdomain);

uchar *fill_a_record_in_msg(struct hlpc *h, uchar * from, uchar * to,
                            uint ttl);
uchar *fill_name_in_msg(struct hlpc *h, uchar * to, int idx);
uchar *fill_header_in_msg(struct setheader *sh);
int fill_rrset_in_buffer(uchar *, uchar *, uchar *, int, int,
                         struct hlpp *);
int transfer_record_to_msg(uchar *, uchar * td, uchar * buf, int buflen,
                           uint16_t *);

void passer_dns_data(mbuf_type *mbuf);
uchar *process_rdata(struct hlpp *, uchar *, int);

int check_qo(struct qoutinfo *qo);
uchar *dbg_print_label(uchar * label, int visible);
uchar *dbg_print_domain(uchar * hdr, uchar * itor);
void dbg_print_ip(uchar * ip, enum rrtype type);
int dbg_print_td(uchar * td);

int insert_into_ttltree(struct rbtree *rbt, uchar * td, int len, int type, uint ttl, packet_type *lowerdomain);
#endif
