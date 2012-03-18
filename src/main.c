#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <paths.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "boltun.h"

struct options opts;
struct ipip cur_local, new_local, cur_remote, new_remote;
int routes_num;
int sock_ctl;

static void get_local_ip(void) {
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sin = (struct sockaddr_in *) &ifr.ifr_addr;

    ifr.ifr_addr.sa_family = AF_INET;

    strcpy(ifr.ifr_name, opts.paid_ifname);

    if (ioctl(sock_ctl, SIOCGIFADDR, &ifr) < 0) {
	syslog(LOG_ERR, "ERROR: reading ip address on %s", opts.paid_ifname);
	return;
    }

    new_local.paid_ip = sin->sin_addr;

    strcpy(ifr.ifr_name, opts.free_ifname);

    if (ioctl(sock_ctl, SIOCGIFADDR, &ifr)) {
	syslog(LOG_ERR, "ERROR: reading ip address on %s", opts.free_ifname);
	return;
    }

    new_local.free_ip = sin->sin_addr;

    if (opts.verbose)
	syslog(LOG_INFO, "get_local_ip(): paid_ip -> %u.%u.%u.%u, free_ip -> %u.%u.%u.%u",
	    IP_PARTS(new_local.paid_ip.s_addr), IP_PARTS(new_local.free_ip.s_addr));
}

static void get_remote_ip(void) {
    int sd;
    struct timeval tv = {opts.timeout, 0};
    struct sockaddr_in server;
    struct hostent *he;

    memset(&server, 0, sizeof(server));

    if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
	syslog(LOG_ERR, "ERROR: creating DGRAM socket");
	return;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(opts.port);

    if (!inet_aton(opts.server, &server.sin_addr)) {
	if (!(he = gethostbyname(opts.server))) {
	    syslog(LOG_ERR, "ERROR: host %s not found", opts.server);
	    close(sd);
	    return;
	}
	memcpy(&server.sin_addr, he->h_addr, sizeof(server.sin_addr));
    }

    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sendto(sd, &new_local, sizeof(new_local), 0, (struct sockaddr *) &server, sizeof(server)))
	if (recvfrom(sd, &new_remote, sizeof(new_remote), 0, NULL, NULL) == EOF)
	    syslog(LOG_ERR, "ERROR: server %s not answer", opts.server);

    close(sd);

    if (opts.verbose)
	syslog(LOG_INFO, "get_remote_ip(): paid_ip -> %u.%u.%u.%u, free_ip -> %u.%u.%u.%u",
	    IP_PARTS(new_remote.paid_ip.s_addr), IP_PARTS(new_remote.free_ip.s_addr));
}

static void compare_ip(void) {
    if (new_local.paid_ip.s_addr && new_remote.free_ip.s_addr &&
	new_local.free_ip.s_addr && new_remote.paid_ip.s_addr) {

	if (new_local.paid_ip.s_addr != cur_local.paid_ip.s_addr ||
	    new_remote.free_ip.s_addr != cur_remote.free_ip.s_addr) {

	    cur_local.paid_ip = new_local.paid_ip;
	    cur_remote.free_ip = new_remote.free_ip;

	    tunnel_update(opts.send_tunnel);
	}

	if (new_local.free_ip.s_addr != cur_local.free_ip.s_addr ||
	    new_remote.paid_ip.s_addr != cur_remote.paid_ip.s_addr) {

	    cur_local.free_ip = new_local.free_ip;
	    cur_remote.paid_ip = new_remote.paid_ip;

	    tunnel_update(opts.recv_tunnel);
	}
    }
}

static void wait_for_connect(void) {
    int sd;
    struct sockaddr_in client;

    memset(&client, 0, sizeof(client));

    if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
	syslog(LOG_ERR, "ERROR: creating DGRAM socket");
	return;
    }

    client.sin_family = AF_INET;
    client.sin_addr.s_addr = INADDR_ANY;
    client.sin_port = htons(opts.port);

    if (bind(sd, (struct sockaddr *) &client, sizeof(client)) < 0) {
	syslog(LOG_ERR, "ERROR: bind");
	return;
    } else if (opts.verbose) {
	syslog(LOG_INFO, "wait_for_connect(): Listening port %d/udp", opts.port);
    }

    do {
	socklen_t addrlen = sizeof(client);

	if (recvfrom(sd, &new_remote, sizeof(new_remote), 0, (struct sockaddr *) &client, &addrlen)) {
	    if (opts.verbose)
		syslog(LOG_INFO, "wait_for_connect(): Received update from %u.%u.%u.%u", IP_PARTS(client.sin_addr.s_addr));

	    /* Sheck password :) */
	    if (strcmp(new_remote.password, new_local.password)) {
		syslog(LOG_ERR, "ERROR: Invalid password in %u.%u.%u.%u", IP_PARTS(client.sin_addr.s_addr));
	    } else {
		get_local_ip();
		sendto(sd, &new_local, sizeof(new_local), 0, (struct sockaddr *) &client, addrlen);
		compare_ip();
	    }
	}
    } while (opts.daemon);
}

int main(int argc, char **argv) {
    int iostream;
    FILE *pid;

    memset(&cur_local, 0, sizeof(cur_local));
    memset(&new_local, 0, sizeof(new_local));
    memset(&cur_remote, 0, sizeof(cur_remote));
    memset(&new_remote, 0, sizeof(new_remote));
    routes_num = 0;

    openlog(PROG_NAME, LOG_PERROR, LOG_USER);

    read_opts(argc, argv);

    /* Go to background */
    if (opts.daemon) {
	if (fork())
	    exit(EXIT_SUCCESS);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	iostream = open(_PATH_DEVNULL, O_RDWR);
	dup(iostream);
	dup(iostream);

	closelog();
	openlog(PROG_NAME, LOG_PID, LOG_DAEMON);
    }

    if (opts.verbose)
	syslog(LOG_INFO, "main(): Running...");

    if (opts.writepid[0]) {
	if ((pid = fopen(opts.writepid, "w"))) {
	    fprintf(pid, "%u\n", getpid());
	    fclose(pid);
	}
    }

    if ((sock_ctl = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
	syslog(LOG_ERR, "ERROR: Creating DGRAM socket");
	return 1;
    }

    if (opts.mode == MODE_CLIENT) {
	do {
	    get_local_ip();
	    get_remote_ip();
	    compare_ip();
	} while (opts.daemon && !sleep(opts.update));

    } else if (opts.mode == MODE_SERVER)
	wait_for_connect();

    if (routes_num)
	free(opts.route);

    closelog();

    return 0;
}
