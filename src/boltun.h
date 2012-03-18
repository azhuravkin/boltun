#ifndef BYFLY_H
#define BYFLY_H

#define IP_PARTS_NATIVE(n)		\
    (unsigned int)((n) >> 24) & 0xFF,	\
    (unsigned int)((n) >> 16) & 0xFF,	\
    (unsigned int)((n) >> 8)  & 0xFF,	\
    (unsigned int)((n) >> 0)  & 0xFF

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

enum {
    MODE_UNKNOWN,
    MODE_SERVER,
    MODE_CLIENT,

    TUNNEL_ADD,
    TUNNEL_CHANGE,
    TUNNEL_OK
};

struct ipip {
    char password[IFNAMSIZ];
    struct in_addr paid_ip;
    struct in_addr free_ip;
};

struct rt {
    struct in_addr net;
    struct in_addr mask;
    int metric;
};

struct options {
    int mode;
    int port;
    int timeout;
    int update;
    int verbose;
    int daemon;
    struct in_addr ifconfig[2];
    char server[32];
    char paid_ifname[IFNAMSIZ];
    char free_ifname[IFNAMSIZ];
    char send_tunnel[IFNAMSIZ];
    char recv_tunnel[IFNAMSIZ];
    char writepid[64];
    struct rt *route;
};

void tunnel_update(const char *);
void read_opts(int, char **);

#endif
