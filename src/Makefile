# @author     dilfish (zhangpu@dnspod.com)
# @version    0.1
PREFIX?=/usr/local/services/dnspod-sr
INSTALL_BIN=$(PREFIX)/bin
INSTALL_ETC=$(PREFIX)/etc
OBJS=utils.o datas.o net.o storage.o dns.o io.o event.o author.o init.o update.o control.o memory.o
LD=-lm -lc
CC = gcc
SERVER_NAME=dnspod-sr


# ifeq (${T},g)
CFLAGS=-g -Wall# -O3
# else
# CFLAGS=
# endif

all:$(OBJS)
	gcc -o $(SERVER_NAME) $(LD) $(OBJS) -lpthread -g# -O3
#ltcmalloc

#base 3
#misc,data,net
utils.o:utils.h utils.c
datas.o:utils.o datas.h datas.c
net.o:utils.o net.h net.c
storage.o:utils.o storage.h storage.c
control.o:control.c
memory.o:memory.c
#dns protocal,read from/write to config/log file
dns.o:datas.o net.o storage.o dns.h dns.c
io.o:dns.o io.h io.c
#event driven
event.o:net.o event.h event.c
author.o:io.o event.o author.c author.h
update.o:control.o update.c
#start
init.o:author.o init.c


.PHONY : install
install:
	@mkdir -p $(INSTALL_BIN)
	cp -f $(SERVER_NAME) $(INSTALL_BIN)
	@mkdir -p $(INSTALL_ETC)
	cp -f ../sr.conf $(INSTALL_ETC)
	cp -f ../root.z $(INSTALL_ETC)
	cp -f ../records.z $(INSTALL_ETC)

.PHONY : uninstall
uninstall:
	rm -f $(INSTALL_BIN)/$(SERVER_NAME)
	rm -f $(INSTALL_ETC)/sr.conf
	rm -f $(INSTALL_ETC)/records.z
	rm -f $(INSTALL_ETC)/root.z

.PHONY : clean
clean:
	rm -f $(OBJS) dnspod-sr

