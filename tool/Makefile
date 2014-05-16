CC = gcc
CFLAGS = -Wall

all: CFLAGS += -g
all: client

client: client.o
	$(CC) $^ -o $@ $(CFLAGS)

.PHONY: clean
clean:
	rm -fr *.o client

