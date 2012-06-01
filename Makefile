# @author     dilfish (zhangpu@dnspod.com)
# @version    0.1
OBJS=utils.o datas.o net.o storage.o dns.o io.o event.o author.o init.o
LD=-lm -lc

ifeq (${T},g)
CFLAGS=-g
else
CFLAGS=
endif

all:$(OBJS)
	gcc -o dnspod-sr $(LD) $(OBJS) -lpthread
#ltcmalloc

#base 3
#misc,data,net
utils.o:utils.h utils.c
datas.o:utils.o datas.h datas.c
net.o:utils.o net.h net.c
storage.o:utils.o storage.h storage.c
#dns protocal,read from/write to config/log file
dns.o:datas.o net.o storage.o dns.h dns.c
io.o:dns.o io.h io.c
#event driven
event.o:net.o event.h event.c
author.o:io.o event.o author.c author.h
#start
init.o:author.o init.c

.PHONY : clean
clean:
	rm -f $(OBJS) dnspod-sr
