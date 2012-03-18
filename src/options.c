#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <crypt.h>
#include <syslog.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "boltun.h"

extern struct options opts;
extern struct ipip new_local;
extern int routes_num;

static void error(void) {
    syslog(LOG_ERR, "Use --help for more information.");
    exit(EXIT_FAILURE);
}

static void usage(void) {
    fprintf(stderr,
	"Usage: %s [Options]\n"
	"Options:\n"
	"  -m, --mode (client|server)\n"
	"  -c, --config <file>\n"
	"  -s, --server <hostname>\n"
	"  -p, --port <num>\n"
	"  -i, --ifconfig \"<local> <remote>\"\n"
	"  -r, --route \"<network> <mask> [metric]\"\n"
	"  -w, --writepid <file>\n"
	"  -d, --daemon\n"
	"  -h, --help\n"
	"  -v, --verbose\n"
	"  -t, --timeout <sec>         default: 1\n"
	"  -u, --update <sec>          default: 60\n"
	"  -P, --paid_ifname <ifname>  default: ppp0\n"
	"  -F, --free_ifname <ifname>  default: ppp1\n"
	"  -S, --send_tunnel <ifname>  default: send0\n"
	"  -R, --recv_tunnel <ifname>  default: recv0\n", PROG_NAME);

    exit(EXIT_FAILURE);
}

static void read_conf(const char *config) {
    FILE *fp;
    char buf[1024];
    char *arg, *val;

    if ((fp = fopen(config, "r")) == NULL) {
	syslog(LOG_ERR, "ERROR: reading %s", config);
	exit(EXIT_FAILURE);
    }

    while (fgets(buf, sizeof(buf), fp)) {
	if ((buf[0] == '#') || (buf[0] == '\n'))
	    continue;

	arg = strtok(buf, " \t\n:");

	/* Arguments without options */
	if (!strcmp(arg, "verbose")) {
	    opts.verbose++;
	    continue;
	} else if (!strcmp(arg, "daemon")) {
	    opts.daemon++;
	    continue;
	}

	if (!(val = strtok(NULL, " \t\n:"))) {
	    syslog(LOG_ERR, "Empty value for option '%s'", arg);
	    continue;
	}

	if (!strcmp(arg, "mode")) {
	    if (!strcmp(val, "client"))
		opts.mode = MODE_CLIENT;
	    else if (!strcmp(val, "server"))
		opts.mode = MODE_SERVER;
	    else
		syslog(LOG_ERR, "ERROR: value for option '%s'", arg);
	    continue;
	} else if (!strcmp(arg, "server")) {
	    snprintf(opts.server, sizeof(opts.server), "%s", val);
	    continue;
	} else if (!strcmp(arg, "ifconfig")) {
	    if (!inet_aton(val, &opts.ifconfig[0])) {
		syslog(LOG_ERR, "ERROR: value for option 'ifconfig[0]': %s", val);
		error();
	    }
	    if (!(val = strtok(NULL, " \t\n:")) || !inet_aton(val, &opts.ifconfig[1])) {
		syslog(LOG_ERR, "ERROR: value for option 'ifconfig[1]': %s", val);
		error();
	    }
	    continue;
	} else if (!strcmp(arg, "route")) {
	    if (!(opts.route = realloc(opts.route, sizeof(struct rt) * (routes_num + 1)))) {
		syslog(LOG_ERR, "ERROR: realloc() return NULL");
		error();
	    }
	    memset(&opts.route[routes_num], 0, sizeof(struct rt));

	    if (!inet_aton(val, &opts.route[routes_num].net)) {
		syslog(LOG_ERR, "ERROR: value for option 'route[0]': %s", val);
		error();
	    }
	    if (!(val = strtok(NULL, " \t\n:")) || !inet_aton(val, &opts.route[routes_num].mask)) {
		syslog(LOG_ERR, "ERROR: value for option 'route[1]': %s", val);
		error();
	    }
	    if ((val = strtok(NULL, " \t\n:"))) {
		opts.route[routes_num].metric = atoi(val);
	    }
	    routes_num++;
	    continue;
	} else if (!strcmp(arg, "port")) {
	    opts.port = atoi(val);
	    continue;
	} else if (!strcmp(arg, "timeout")) {
	    opts.timeout = atoi(val);
	    continue;
	} else if (!strcmp(arg, "update")) {
	    opts.update = atoi(val);
	    continue;
	} else if (!strcmp(arg, "paid_ifname")) {
	    snprintf(opts.paid_ifname, sizeof(opts.paid_ifname), "%s", val);
	    continue;
	} else if (!strcmp(arg, "free_ifname")) {
	    snprintf(opts.free_ifname, sizeof(opts.free_ifname), "%s", val);
	    continue;
	} else if (!strcmp(arg, "send_tunnel")) {
	    snprintf(opts.send_tunnel, sizeof(opts.send_tunnel), "%s", val);
	    continue;
	} else if (!strcmp(arg, "recv_tunnel")) {
	    snprintf(opts.recv_tunnel, sizeof(opts.recv_tunnel), "%s", val);
	    continue;
	} else if (!strcmp(arg, "writepid")) {
	    snprintf(opts.writepid, sizeof(opts.writepid), "%s", val);
	    continue;
	} else if (!strcmp(arg, "password")) {
	    strcpy(new_local.password, crypt(val, "ok"));
	    continue;
	} else {
	    syslog(LOG_ERR, "ERROR: unknown option '%s'", arg);
	    exit(EXIT_FAILURE);
	}
    }

    fclose(fp);
}

void read_opts(int argc, char **argv) {
    int opt;
    char *p;

    memset(&opts, 0, sizeof(opts));

    /* Default values */
    opts.timeout = 1;
    opts.update = 60;
    strcpy(opts.paid_ifname, "ppp0");
    strcpy(opts.free_ifname, "ppp1");
    strcpy(opts.send_tunnel, "send0");
    strcpy(opts.recv_tunnel, "recv0");

    struct option long_opts[] = {
	{"mode",	required_argument, NULL, 'm'},
	{"config",	required_argument, NULL, 'c'},
	{"server",	required_argument, NULL, 's'},
	{"ifconfig",	required_argument, NULL, 'i'},
	{"route",	required_argument, NULL, 'r'},
	{"port",	required_argument, NULL, 'p'},
	{"timeout",	required_argument, NULL, 't'},
	{"update",	required_argument, NULL, 'u'},
	{"paid_ifname",	required_argument, NULL, 'P'},
	{"free_ifname",	required_argument, NULL, 'F'},
	{"send_tunnel",	required_argument, NULL, 'S'},
	{"recv_tunnel",	required_argument, NULL, 'R'},
	{"writepid",	required_argument, NULL, 'w'},
	{"daemon",	no_argument,       NULL, 'd'},
	{"help",	no_argument,       NULL, 'h'},
	{"verbose",	no_argument,       NULL, 'v'},
	{0, 0, 0, 0}
    };

    /* Parse command line options. */
    while ((opt = getopt_long(argc, argv, "m:c:s:i:g:p:t:u:P:F:S:R:w:dhv", long_opts, NULL)) != EOF) {
	switch (opt) {
	    case 'm':
		if (!strcmp(optarg, "client")) {
		    opts.mode = MODE_CLIENT;
		} else if (!strcmp(optarg, "server")) {
		    opts.mode = MODE_SERVER;
		} else {
		    syslog(LOG_ERR, "ERROR: value for option 'mode': %s", optarg);
		    error();
		}
		break;
	    case 'c':
		read_conf(optarg);
		break;
	    case 's':
		snprintf(opts.server, sizeof(opts.server), "%s", optarg);
		break;
	    case 'i':
		if (!(p = strtok(optarg, " \t")) || !inet_aton(p, &opts.ifconfig[0])) {
		    syslog(LOG_ERR, "ERROR: value for option 'ifconfig[0]': %s", p);
		    error();
		}
		if (!(p = strtok(NULL, " \t")) || !inet_aton(p, &opts.ifconfig[1])) {
		    syslog(LOG_ERR, "ERROR: value for option 'ifconfig[1]': %s", p);
		    error();
		}
		break;
	    case 'r':
		if (!(opts.route = realloc(opts.route, sizeof(struct rt) * (routes_num + 1)))) {
		    syslog(LOG_ERR, "ERROR: realloc() return NULL");
		    error();
		}
		memset(&opts.route[routes_num], 0, sizeof(struct rt));

		if (!(p = strtok(optarg, " \t")) || !inet_aton(p, &opts.route[routes_num].net)) {
		    syslog(LOG_ERR, "ERROR: value for option 'route[0]': %s", p);
		    error();
		}
		if (!(p = strtok(NULL, " \t")) || !inet_aton(p, &opts.route[routes_num].mask)) {
		    syslog(LOG_ERR, "ERROR: value for option 'route[1]': %s", p);
		    error();
		}
		if ((p = strtok(NULL, " \t"))) {
		    opts.route[routes_num].metric = atoi(p);
		}
		routes_num++;
		break;
	    case 'p':
		opts.port = atoi(optarg);
		break;
	    case 't':
		opts.timeout = atoi(optarg);
		break;
	    case 'u':
		opts.update = atoi(optarg);
		break;
	    case 'P':
		snprintf(opts.paid_ifname, sizeof(opts.paid_ifname), "%s", optarg);
		break;
	    case 'F':
		snprintf(opts.paid_ifname, sizeof(opts.free_ifname), "%s", optarg);
		break;
	    case 'S':
		snprintf(opts.paid_ifname, sizeof(opts.send_tunnel), "%s", optarg);
		break;
	    case 'R':
		snprintf(opts.paid_ifname, sizeof(opts.recv_tunnel), "%s", optarg);
		break;
	    case 'w':
		snprintf(opts.writepid, sizeof(opts.writepid), "%s", optarg);;
		break;
	    case 'd':
		opts.daemon++;
		break;
	    case 'v':
		opts.verbose++;
		break;
	    case 'h':
		usage();
		break;
	    default:
		error();
		break;
	}
    }

    /* Check of mandatory options */
    if (opts.mode == MODE_UNKNOWN) {
	syslog(LOG_ERR, "ERROR: Option 'mode' is not set");
	error();
    } else if ((opts.mode == MODE_CLIENT) && !strlen(opts.server)) {
	syslog(LOG_ERR, "ERROR: Option 'server' is not set");
	error();
    } else if (!opts.port) {
	syslog(LOG_ERR, "ERROR: Option 'port' is not set");
	error();
    }
}
