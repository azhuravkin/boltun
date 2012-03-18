#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/route.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include "boltun.h"

extern struct options opts;
extern struct ipip cur_local, new_local, cur_remote, new_remote;
extern int sock_ctl;
extern int routes_num;

static void create_routes(void) {
    int i;
    struct rtentry rt;
    struct sockaddr_in *sin;

    for (i = 0; i < routes_num; i++) {
	memset(&rt, 0, sizeof(rt));

	sin = (struct sockaddr_in *) &rt.rt_dst;
	sin->sin_family = AF_INET;
	sin->sin_addr = opts.route[i].net;

	sin = (struct sockaddr_in *) &rt.rt_genmask;
	sin->sin_family = AF_INET;
	sin->sin_addr = opts.route[i].mask;

	if (opts.route[i].mask.s_addr == 0xFFFFFFFF)
	    rt.rt_flags |= RTF_HOST;

	rt.rt_flags |= RTF_UP;
	rt.rt_dev = opts.send_tunnel;
	rt.rt_metric = opts.route[i].metric + 1;

	if (ioctl(sock_ctl, SIOCADDRT, &rt) < 0) {
	    syslog(LOG_ERR, "ERROR: creating route %u.%u.%u.%u/%u.%u.%u.%u",
		IP_PARTS(opts.route[i].net.s_addr),
		IP_PARTS(opts.route[i].mask.s_addr));
	    continue;
	}

	if (opts.verbose) {
	    syslog(LOG_INFO, "create_routes(): ip route add %u.%u.%u.%u/%u.%u.%u.%u dev %s metric %d",
		IP_PARTS(opts.route[i].net.s_addr),
		IP_PARTS(opts.route[i].mask.s_addr),
		opts.send_tunnel,
		opts.route[i].metric);
	}
    }
}

static void set_ip_address(void) {
    struct ifreq ifr;
    struct sockaddr_in sin;

    if (!opts.ifconfig[0].s_addr || !opts.ifconfig[1].s_addr)
	return;

    if (opts.verbose)
        syslog(LOG_INFO, "set_ip_address(): ip addr add %u.%u.%u.%u peer %u.%u.%u.%u dev %s",
	    IP_PARTS(opts.ifconfig[0].s_addr), IP_PARTS(opts.ifconfig[1].s_addr),
	    opts.send_tunnel);

    strcpy(ifr.ifr_name, opts.send_tunnel);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = opts.ifconfig[0];
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

    if (ioctl(sock_ctl, SIOCSIFADDR, &ifr) < 0) {
	syslog(LOG_ERR, "ERROR: setting ip address");
	return;
    }

    sin.sin_addr = opts.ifconfig[1];
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

    if (ioctl(sock_ctl, SIOCSIFDSTADDR, &ifr) < 0)
	syslog(LOG_ERR, "ERROR: setting destination ip address");

    create_routes();
}

static void tunnel_change(struct ip_tunnel_parm *parm) {
    struct ifreq ifr;

    strcpy(ifr.ifr_name, parm->name);

    ifr.ifr_ifru.ifru_data = (void *) parm;

    if (ioctl(sock_ctl, SIOCCHGTUNNEL, &ifr) < 0)
	syslog(LOG_ERR, "ERROR: changing tunnel %s", parm->name);
    else
	syslog(LOG_INFO, "Changing tunnel %s (%u.%u.%u.%u peer %u.%u.%u.%u)",
	    parm->name,
	    IP_PARTS(parm->iph.saddr),
	    IP_PARTS(parm->iph.daddr));
}

static void tunnel_add(struct ip_tunnel_parm *parm) {
    struct ifreq ifr;

    strcpy(ifr.ifr_name, "tunl0");

    ifr.ifr_ifru.ifru_data = (void *) parm;

    if (ioctl(sock_ctl, SIOCADDTUNNEL, &ifr) < 0)
	syslog(LOG_ERR, "ERROR: creating tunnel %s", parm->name);
    else
	syslog(LOG_INFO, "tunnel_add(): Creating tunnel %s (%u.%u.%u.%u peer %u.%u.%u.%u)",
	    parm->name,
	    IP_PARTS(parm->iph.saddr),
	    IP_PARTS(parm->iph.daddr));
}

static void tunnel_up(struct ip_tunnel_parm *parm) {
    struct ifreq ifr;

    ifr.ifr_ifru.ifru_data = (void *) parm;

    strcpy(ifr.ifr_name, parm->name);

    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_NOARP;

    if (ioctl(sock_ctl, SIOCSIFFLAGS, &ifr) < 0)
	syslog(LOG_ERR, "ERROR: upping iface %s", parm->name);

    if (!strcmp(parm->name, opts.send_tunnel)) {
	set_ip_address();
    }
}

static int tunnel_get(struct ip_tunnel_parm *parm) {
    struct ifreq ifr;
    struct ip_tunnel_parm p;

    strcpy(ifr.ifr_name, parm->name);
    ifr.ifr_ifru.ifru_data = (void *) &p;

    if (ioctl(sock_ctl, SIOCGETTUNNEL, &ifr) < 0)
	return TUNNEL_ADD;

    if (p.iph.saddr == parm->iph.saddr && p.iph.daddr == parm->iph.daddr)
	return TUNNEL_OK;

    return TUNNEL_CHANGE;
}

void tunnel_update(const char *name) {
    struct ip_tunnel_parm p;

    memset(&p, 0, sizeof(p));

    p.iph.version = 4;
    p.iph.ihl = sizeof(struct iphdr) >> 2;
    p.iph.protocol = IPPROTO_IPIP;

    strcpy(p.name, name);

    if (strcmp(name, opts.send_tunnel)) {
	p.iph.saddr = new_local.free_ip.s_addr;
	p.iph.daddr = new_remote.paid_ip.s_addr;
    } else {
	p.iph.saddr = new_local.paid_ip.s_addr;
	p.iph.daddr = new_remote.free_ip.s_addr;
    }

    switch (tunnel_get(&p)) {
    case TUNNEL_ADD:
	tunnel_add(&p);
	tunnel_up(&p);
	break;
    case TUNNEL_CHANGE:
	tunnel_change(&p);
	break;
    case TUNNEL_OK:
	if (opts.verbose) {
	    syslog(LOG_INFO, "tunnel_update(): Tunnel %s already exist", name);
	}
	break;
    }
}
