#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 1922
#define ONE_SPLICE_TRANSFER_SIZE 4096
#define MAX_EPOLL_EVENT_LIST_NUM 1024

static int connect_to(char *ip, int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Failed to create socket.\n");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("Failed to connect.\n");
        return -1;
    }

    return sockfd;
}

static int add_to_epoll(int epoll_fd, int fd, uint32_t events, void *usr_data)
{
    struct epoll_event ep_evt;
    ep_evt.events = events;
    ep_evt.data.ptr = usr_data;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ep_evt);
}

static int remove_from_epoll(int epoll_fd, int fd)
{
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

typedef struct _conn_ctx_t conn_ctx_t;

typedef int (*CONN_EVT_HANDLER)(conn_ctx_t *ctx, uint32_t epoll_events);

typedef void (*CONN_CTX_RELEASER)(conn_ctx_t *ctx);

struct _conn_ctx_t {
    int fd;
    conn_ctx_t *next;
    conn_ctx_t *companion_ctx;
    CONN_EVT_HANDLER handler;
    CONN_CTX_RELEASER releaser;
};

typedef struct _accept_ctx_t {
    conn_ctx_t conn_ctx;
    int epoll_fd;
    char *target_ip;
    int target_port;
} accept_ctx_t;

typedef struct _client_ctx_t client_ctx_t;
typedef struct _target_ctx_t target_ctx_t;

struct _client_ctx_t {
    conn_ctx_t conn_ctx;
    int pipe_fds[2];
};

struct _target_ctx_t {
    conn_ctx_t conn_ctx;
};

static int move(int in_fd, int out_fd, int pip[2])
{
    int ret = splice(in_fd, NULL, pip[1], NULL, ONE_SPLICE_TRANSFER_SIZE,
                     SPLICE_F_MOVE);
    if (ret == -1) {
        printf("splice error\n");
        return -1;
    }
    if (ret == 0) {
        return 0;
    }

    ret = splice(pip[0], NULL, out_fd, NULL, ONE_SPLICE_TRANSFER_SIZE,
                 SPLICE_F_MOVE);
    if (ret == -1) {
        printf("splice error\n");
        return -1;
    }
    return ret;
}

static int client_handler(conn_ctx_t *ctx, uint32_t epoll_events)
{
    client_ctx_t *cli_ctx = (client_ctx_t *) ctx;
    if (epoll_events & EPOLLIN) {
        int ret = move(ctx->fd, ctx->companion_ctx->fd, cli_ctx->pipe_fds);
        if (ret <= 0) {
            return -1;
        }
    }
    return 0;
}

static void client_releaser(conn_ctx_t *ctx)
{
    client_ctx_t *cli_ctx = (client_ctx_t *) ctx;
    if (cli_ctx->pipe_fds[0] >= 0)
        close(cli_ctx->pipe_fds[0]);
    if (cli_ctx->pipe_fds[1] >= 0)
        close(cli_ctx->pipe_fds[1]);
}

static client_ctx_t *client_ctx_init(int fd,
                                     CONN_EVT_HANDLER evt_hdlr,
                                     CONN_CTX_RELEASER rlsr)
{
    client_ctx_t *cli_ctx = malloc(sizeof(client_ctx_t));
    if (!cli_ctx) {
        return NULL;
    }
    int ret = pipe(cli_ctx->pipe_fds);
    if (ret != 0) {
        free(cli_ctx);
        return NULL;
    }
    cli_ctx->conn_ctx.fd = fd;
    cli_ctx->conn_ctx.handler = evt_hdlr;
    cli_ctx->conn_ctx.releaser = rlsr;
    cli_ctx->conn_ctx.next = NULL;
    cli_ctx->conn_ctx.companion_ctx = NULL;

    return cli_ctx;
}

static int target_handler(conn_ctx_t *ctx, uint32_t epoll_events)
{
    client_ctx_t *cli_ctx = (client_ctx_t *) ctx->companion_ctx;
    if (epoll_events & EPOLLIN) {
        int ret = move(ctx->fd, ctx->companion_ctx->fd, cli_ctx->pipe_fds);
        if (ret <= 0) {
            return -1;
        }
    }
    return 0;
}

static target_ctx_t *target_ctx_init(int fd,
                                     CONN_EVT_HANDLER evt_hdlr,
                                     CONN_CTX_RELEASER rlsr)
{
    target_ctx_t *tar_ctx = malloc(sizeof(target_ctx_t));
    if (!tar_ctx) {
        return NULL;
    }
    tar_ctx->conn_ctx.fd = fd;
    tar_ctx->conn_ctx.handler = evt_hdlr;
    tar_ctx->conn_ctx.releaser = rlsr;
    tar_ctx->conn_ctx.next = NULL;
    tar_ctx->conn_ctx.companion_ctx = NULL;

    return tar_ctx;
}

static int accept_handler(conn_ctx_t *ctx, uint32_t epoll_events)
{
    accept_ctx_t *acpt_ctx = (accept_ctx_t *) ctx;
    if (epoll_events & EPOLLIN) {
        int connfd = accept(ctx->fd, (struct sockaddr *) NULL, NULL);
        int target_fd = connect_to(acpt_ctx->target_ip, acpt_ctx->target_port);
        if (target_fd >= 0) {
            client_ctx_t *cli_ctx =
                client_ctx_init(connfd, client_handler, client_releaser);
            if (!cli_ctx) {
                close(connfd);
                close(target_fd);
                return 0;
            }

            target_ctx_t *tar_ctx =
                target_ctx_init(target_fd, target_handler, NULL);
            if (!tar_ctx) {
                client_releaser((conn_ctx_t *) cli_ctx);
                free(cli_ctx);
                close(connfd);
                close(target_fd);
                return 0;
            }

            ((conn_ctx_t *) cli_ctx)->companion_ctx = (conn_ctx_t *) tar_ctx;
            ((conn_ctx_t *) tar_ctx)->companion_ctx = (conn_ctx_t *) cli_ctx;

            int ret =
                add_to_epoll(acpt_ctx->epoll_fd, connfd, EPOLLIN, cli_ctx);
            assert(ret == 0);
            ret = add_to_epoll(acpt_ctx->epoll_fd, target_fd, EPOLLIN, tar_ctx);
            assert(ret == 0);
        } else {
            close(connfd);
        }
    }
    return 0;
}

static accept_ctx_t *accept_ctx_init(int fd,
                                     CONN_EVT_HANDLER evt_hdlr,
                                     CONN_CTX_RELEASER rlsr,
                                     char *ip,
                                     int port,
                                     int epoll_fd)
{
    accept_ctx_t *acpt_ctx = malloc(sizeof(accept_ctx_t));
    if (!acpt_ctx) {
        return NULL;
    }
    acpt_ctx->conn_ctx.fd = fd;
    acpt_ctx->conn_ctx.handler = evt_hdlr;
    acpt_ctx->conn_ctx.releaser = rlsr;
    acpt_ctx->conn_ctx.next = NULL;
    acpt_ctx->conn_ctx.companion_ctx = NULL;
    acpt_ctx->epoll_fd = epoll_fd;
    acpt_ctx->target_ip = ip;
    acpt_ctx->target_port = port;

    return acpt_ctx;
}

static void release_list_add(int epoll_fd,
                             conn_ctx_t *list_head,
                             conn_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    for (conn_ctx_t *chk_ctx = list_head; chk_ctx; chk_ctx = chk_ctx->next) {
        if (chk_ctx->next == ctx) {
            /* ctx is already in release list */
            return;
        }
        if (chk_ctx->next == NULL) {
            /* append ctx to release list */
            remove_from_epoll(epoll_fd, ctx->fd);
            chk_ctx->next = ctx;
            return;
        }
    }
}

static void release_list_cleanup(conn_ctx_t *list_head)
{
    while (list_head->next) {
        conn_ctx_t *rls_ctx = list_head->next;
        list_head->next = rls_ctx->next;

        close(rls_ctx->fd);
        if (rls_ctx->releaser) {
            rls_ctx->releaser(rls_ctx);
        }
        free(rls_ctx);
    }
}

static int proxy(int epoll_fd)
{
    struct epoll_event ev_list[MAX_EPOLL_EVENT_LIST_NUM];
    conn_ctx_t release_list;
    release_list.next = NULL;

    int ret = 0;
    while ((ret = epoll_wait(epoll_fd, ev_list,
                             sizeof(ev_list) / sizeof(ev_list[0]), 1000)) !=
           -1) {
        if (ret == 0) {
            continue;
        }
        int evt_num = ret;
        for (int i = 0; i < evt_num; ++i) {
            conn_ctx_t *conn_ctx = (conn_ctx_t *) ev_list[i].data.ptr;
            if (conn_ctx && conn_ctx->handler) {
                ret = conn_ctx->handler(conn_ctx, ev_list->events);
                if (ret != 0) {
                    // add to release list
                    release_list_add(epoll_fd, &release_list, conn_ctx);
                    release_list_add(epoll_fd, &release_list,
                                     conn_ctx->companion_ctx);
                }
            }
        }
        release_list_cleanup(&release_list);
    }
    return ret;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <target IP address> <target port>\n",
                argv[0]);
        return -1;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        printf("epoll_create1 fail!\n");
        return -1;
    }

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    int optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    bind(listenfd, (struct sockaddr *) &addr, sizeof(addr));

    listen(listenfd, 1);

    accept_ctx_t *acpt_ctx = accept_ctx_init(listenfd, accept_handler, NULL,
                                             argv[1], atoi(argv[2]), epoll_fd);
    if (!acpt_ctx) {
        printf("accept_ctx_init fail!\n");
        return -1;
    }

    int ret = add_to_epoll(epoll_fd, listenfd, EPOLLIN, acpt_ctx);
    assert(ret == 0);

    ret = proxy(epoll_fd);

    remove_from_epoll(epoll_fd, listenfd);
    free(acpt_ctx);
    close(listenfd);
    close(epoll_fd);

    return 0; /* should not reach here */
}
