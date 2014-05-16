#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#define CLI_PATH    "/tmp/"
const char *local_socket_name = "/tmp/foo.socket";

int create_local_client(const char *name)
{
    int sock, len, ret;
    struct sockaddr_un addr;
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket error");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s%05d", CLI_PATH, getpid());
    len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);

    unlink(addr.sun_path);

    ret = bind(sock, (struct sockaddr *)&addr, len);
    if (ret < 0) {
        perror("bind error");
        close(sock);
        return -2;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, name);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(name);
    ret = connect(sock, (struct sockaddr *)&addr, len);
    if (ret < 0) {
        perror("connect error");
        close(sock);
        return -3;
    }
    return sock;
}

void set_signal_catcher()
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    sigaction(SIGPIPE, &action, NULL);
}

int main(int argc, char const* argv[])
{
    int sock, ret;
    char send_buf[BUFSIZ] = {0};
    char recv_buf[BUFSIZ];
    /* char *line = NULL; */
    sock = create_local_client(local_socket_name);
    if (sock < 0) {
        fprintf(stderr, "connect to server failed\n");
        return -1;
    }
    set_signal_catcher();

    while (1) {
        /* memset(send_buf, 0, BUFSIZ); */
        /* line = fgets(send_buf, BUFSIZ - 1, stdin); */
        /* if (!line) { */
            /* break; */
        /* } */
        /* if (strcmp(send_buf, "quit") == 0) { */
            /* break; */
        /* } */
        strcpy(send_buf, argv[1]);
        ret = send(sock, send_buf, strlen(send_buf), 0);
        if (ret > 0) {
            memset(recv_buf, 0, BUFSIZ);
            recv(sock, recv_buf, BUFSIZ - 1, 0);
            if (recv_buf[0] != '\0') {
                printf("%s\n", recv_buf);
            }
            break;
        } else {
            printf("disconnect with server\n");
            break;
        }
    }
    close(sock);
    return 0;
}

