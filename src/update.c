#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <errno.h>
#include "update.h"
#include "author.h"
#include "control.h"

#define USELESS 1
#define MAX_CONN 1024

const char *local_socket_name = "/tmp/foo.socket";

int create_local_server(const char *path)
{
    int sock, size, ret;
    struct sockaddr_un addr;
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket error");
        return -1;
    }
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    size = offsetof(struct sockaddr_un, sun_path) + strlen(path);

    unlink(addr.sun_path);
    ret = bind(sock, (struct sockaddr *)&addr, size);
    if (ret < 0) {
        perror("bind error");
        close(sock);
        return -2;
    }

    ret = listen(sock, 10);
    if (ret < 0) {
        perror("listen error");
        close(sock);
        return -3;
    }
    return sock;
}

int ctl_fd(int epfd, int fd, int ctl, uint32_t events)
{
    int ret;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.data.fd = fd;
    if (ctl == EPOLL_CTL_ADD) {
        ev.events = events;
    }

    if ((ret = epoll_ctl(epfd, ctl, fd, &ev)) < 0) {
        perror("epoll_ctl");
        fprintf(stderr, "ctl fd %d error\n", fd);
        return -1;
    }
    return 0;
}

int accept_client(int epfd, int sock)
{
    int clifd;
    socklen_t len;
    struct sockaddr_un cli_addr;
    struct stat statbuf;
    struct timeval tv;
    char *tmp = NULL;
    len = sizeof(cli_addr);
    clifd = accept(sock, (struct sockaddr *)&cli_addr, &len);
    if (clifd < 0) {
        fprintf(stderr, "accept error\n");
        close(clifd);
        return -1;
    }
    len -= offsetof(struct sockaddr_un, sun_path);
    if (len > 0) {
        cli_addr.sun_path[len] = '\0';
        if (stat(cli_addr.sun_path, &statbuf) < 0) {
            fprintf(stderr, "no this socket\n");
            close(clifd);
            return -2;
        }
        if (S_ISSOCK(statbuf.st_mode) == 0) {
            fprintf(stderr, "not a socket\n");
            close(clifd);
            return -3;
        }
        unlink(cli_addr.sun_path);
        tmp = strrchr(cli_addr.sun_path, '/');
        if (tmp) {
            printf("client pid: %s connected: %d\n", tmp + 1, clifd);
        }
    } else {
        printf("new client (unknown pid) connected: %d\n", clifd);
    }

    if (ctl_fd(epfd, clifd, EPOLL_CTL_ADD, EPOLLIN)) {
        close(clifd);
        return -1;
    }
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(clifd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return clifd;
}

void disconnect_client(int epfd, int client)
{
    ctl_fd(epfd, client, EPOLL_CTL_DEL, 0);
    close(client);
    printf("disconnect with client %d\n", client);
}

uint16_t get_type_from_str(const char *str_type)
{
    uint16_t type = 0;
    if (!str_type || str_type[0] == '\0') {
        type = A;
    } else if (strcmp(str_type, "A") == 0) {
        type = A;
    } else if (strcmp(str_type, "CNAME") == 0) {
        type = CNAME;
    } else if (strcmp(str_type, "AAAA") == 0) {
        type = AAAA;
    } else if (strcmp(str_type, "MX") == 0) {
        type = MX;
    } else if (strcmp(str_type, "TXT") == 0) {
        type = TXT;
    } else if (strcmp(str_type, "SRV") == 0) {
        type = SRV;
    } else if (strcmp(str_type, "NS") == 0) {
        type = NS;
    } else if (strcmp(str_type, "SOA") == 0) {
        type = SOA;
    } else if (strcmp(str_type, "PTR") == 0) {
        type = PTR;
    } else {
        dns_error(1, "invalid cache flush type");
    }
    return type;
}

int cmd_analyze(char *str, uchar *domain, uint16_t *type)
{
    uchar *p = (uchar *)strchr(str, ':');
    uchar *temp = NULL;
    uchar str_type[32] = {0};
    size_t len;
    int cmd_type = -1;
    if (!p) {
        if (strcmp(str, "hijack") == 0) {
            cmd_type = HIJACK;
        }
    } else {
        if (strncmp(str, "cache flush", 11) == 0) {
            cmd_type = CACHE_FLUSH;
        } else if (strncmp(str, "hijack", 6) == 0) {
            cmd_type = HIJACK;
        }
        p++;
        temp = jump_space((uchar *)p);
        fix_tail((char *)temp);
        sscanf((const char *)temp, "%s %s", domain, str_type);
        *type = get_type_from_str((const char *)str_type);
        len = strlen((const char *)domain);
        if (domain[len - 1] != '.') {
            domain[len] = '.';
            domain[len + 1] = '\0';
        }
    }
    return cmd_type;
}

int talk_with_client(int epfd, int client, struct server *s)
{
    /*
     * struct htable *ds = s->datasets;
     * struct rbtree *rbt = s->ttlexp;
     */
    char buffer[BUFSIZ] = {0};
    int ret;
    ret = recv(client, buffer, BUFSIZ - 1, 0);
    if (ret == 0) {
        disconnect_client(epfd, client);
    }
    if (ret > 0) {
        printf("recv from client [%d] %d bytes: %s\n", client, ret, buffer);
        uchar domain[512] = {0};
        uint16_t type = 0;
        int ret = cmd_analyze(buffer, domain, &type);
        if (ret == HIJACK) {
            hijack(domain, type, s->datasets, s->ttlexp);
        } else if (ret == CACHE_FLUSH) {
            if (type != 0 && strlen((char *)domain) > 3) {
                cache_flush(domain, type, s->datasets, s->ttlexp);
            }
        }
        send(client, buffer, strlen(buffer), 0);
    }
    return 0;
}

int start_local_server(struct server *s)
{
    int server, ret, epfd, i, fd;
    struct epoll_event e[MAX_CONN];
    server = create_local_server(local_socket_name);
    if (server < 0) {
        return -1;
    }

    epfd = epoll_create(USELESS);
    if (epfd < 0) {
        perror("epoll_create error");
        close(server);
        return -1;
    }
    if (ctl_fd(epfd, server, EPOLL_CTL_ADD, EPOLLIN) != 0) {
        close(server);
        return -1;
    }

    while (1) {
        ret = epoll_wait(epfd, e, MAX_CONN, 1000);
        if (ret < 0) {
            /* perror("epoll_wait error"); */
        } else {
            for (i = 0; i < ret; i++) {
                fd = e[i].data.fd;
                if (fd == server) {
                    accept_client(epfd, server);
                } else {
                    if (e[i].events & EPOLLHUP || e[i].events & EPOLLERR) {
                        disconnect_client(epfd, fd);
                    } else if (e[i].events & EPOLLIN) {
                        talk_with_client(epfd, fd, s);
                    }
                }
            }
        }
    }
}

