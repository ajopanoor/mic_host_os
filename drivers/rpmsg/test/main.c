#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>
#include <features.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "rpmsg_client_ioctl.h"

#define DEV_NAME	"/dev/crpmsg"
#define PMAX		80
#define TEST_INPUT_OPTS		"c:t:n:s:r:e:d:w:z:h"

char path[PMAX];


static void __dump_args(struct rpmsg_test_args *targs)
{
	printf("args: c=%d, t=%d, n=%d, s=%d, r=%d, e=%d d=%d w=%d flags=%x\n",
			targs->remote_cpu, targs->type,
			targs->num_runs, targs->sbuf_size,
			targs->rbuf_size, targs->src_ept,
		        targs->dst_ept, targs->wait, targs->flags);
}

static void __validate_all_args(struct rpmsg_test_args *targs)
{
	__dump_args(targs);
	assert(!(targs->type == -1));
	assert(!(targs->sbuf_size == 0));
	assert(!(targs->rbuf_size == 0));
}

static void __print_usage(void)
{
	fprintf(stderr, "Usage:-\n"
			"rpmsg_client [-c cpu] [-t type] [-n num_runs]\n"
			"\t\t [-s send_size] [-r recv_size] [-e src_ept]\n"
			"\t\t [-d dst_ept] [-w wait] [-z zero-copy]\n");

	fprintf(stderr, "Test Types:-"
			"\n\t(1) RPMSG Ping"
			"\n\t(2) RPMSG Send"
			"\n\t(3) RPMSG Recv\n");
}

static struct rpmsg_test_args *__get_args(int argc, char *argv[])
{
	struct rpmsg_test_args *targs;
	int flags;
	int zero_copy = 0;
	int opt;

	targs = malloc(sizeof(*targs));
	targs->remote_cpu = -1;
	targs->type = -1;
	targs->src_ept = 0;
	targs->dst_ept = 0;
	targs->num_runs = 1;
	targs->wait = 0;
	targs->flags = 0;

	while((opt = getopt(argc, argv, TEST_INPUT_OPTS)) != -1) {
		switch (opt) {
			case 'c':
				targs->remote_cpu = atoi(optarg);
				break;
			case 't':
				targs->type = atoi(optarg);
				break;
			case 'n':
				targs->num_runs = atoi(optarg);
				break;
			case 's':
				targs->sbuf_size = atoi(optarg);
				break;
			case 'r':
				targs->rbuf_size = atoi(optarg);
				break;
			case 'e':
				targs->src_ept = atoi(optarg);
				break;
			case 'd':
				targs->dst_ept = atoi(optarg);
				break;
			case 'w':
				targs->wait = atoi(optarg);
				break;
			case 'z':
				zero_copy = atoi(optarg);
				break;
			case '?':
			case 'h':
			default:
				__print_usage();
				free(targs);
				exit(EXIT_FAILURE);
		}
	}

	if (zero_copy != 0)
		targs->flags |= O_SYNC;

	return targs;
}

void __add_payload(int *buf, int len, bool r)
{
	static unsigned int val;
	unsigned int seed, i, times = len / sizeof(int);
	FILE* urandom = fopen("/dev/urandom", "r");

	if(r){
		fread(&seed, sizeof(int), 1, urandom);
		fclose(urandom);
		srand(seed);
	}

	for(i = 0; i < times; i++)
		buf[i] = r ? rand() : val;

	val++;
}

void __dump_buf(int *buf, int len)
{
	int i, times, t = len/sizeof(int);
	times = t < 16 ? t : 16;

	for(i=0; i < times; i+=4) {
		printf("crpmsg[%d]: %x %x %x %x %x\n",i, buf[i], buf[i+1],
				buf[i+2], buf[i+3]);
	}
}

void rpmsg_cfg_dev(int fd, struct rpmsg_test_args *targs)
{
	int ret;
	ret = ioctl(fd, RPMSG_CFG_DEV_IOCTL, (void *)targs);
	if (ret < 0) {
		printf(" IOCTL failed %s %s\n", path, strerror(errno));
		return;
	}
}

static inline int open_crpmsg_dev(struct rpmsg_test_args *targs)
{
	int fd, id = 0;

	snprintf(path, PATH_MAX, DEV_NAME"%d", id);

	fd = open(path, O_RDWR);
	if (fd < 0)
		printf("Could not open %s %s\n", path, strerror(errno));

	return fd;
}

static void rpmsg_send(struct rpmsg_test_args *targs)
{
	void *sbuf = NULL;
	int i, fd;

	assert(targs->sbuf_size);

	sbuf = malloc(targs->sbuf_size);
	if(!sbuf) {
		printf("malloc failed %s %s\n", path, strerror(errno));
		return;
	}

	if((fd = open_crpmsg_dev(targs)) < 0)
		return;

	rpmsg_cfg_dev(fd, targs);

	for(i = 0; i < targs->num_runs; i++) {
		__add_payload(sbuf, targs->sbuf_size, false);

		if (write(fd, sbuf, targs->sbuf_size) < targs->sbuf_size) {
			printf("Could not write to %s %s\n", path,
					strerror(errno));
			goto err;
		}
	}

	if (targs->wait) while(1);
err:
	free(sbuf);
	close(fd);
}
static void rpmsg_recv(struct rpmsg_test_args *targs)
{
	void *rbuf = NULL;
	int i, fd;

	assert(targs->rbuf_size);

	rbuf = malloc(targs->rbuf_size);
	if(!rbuf) {
		printf("malloc failed %s %s\n", path, strerror(errno));
		return;
	}

	if((fd = open_crpmsg_dev(targs)) < 0)
		return;

	for(i = 0; i < targs->num_runs; i++) {
		if (read(fd, rbuf, targs->rbuf_size) < 0){
			printf("Could not read from %s %s\n", path,
					strerror(errno));
			goto err;
		}
		__dump_buf(rbuf, targs->rbuf_size);
	}
err:
	free(rbuf);
	close(fd);
}


static void rpmsg_ping(struct rpmsg_test_args *targs)
{
	int fd, ret, id = 0;
	unsigned int addr;

	__validate_all_args(targs);

	if((fd = open_crpmsg_dev(targs)) < 0)
		return;

	ret = ioctl(fd, RPMSG_PING_IOCTL, (void *)targs);
	if (ret < 0) {
		printf(" IOCTL failed %s %s\n", path, strerror(errno));
		return;
	}

	if(targs->wait) while(1);

	ret = ioctl(fd, RPMSG_DESTROY_EPT_IOCTL, addr);
	if (ret < 0) {
		printf(" IOCTL failed %s %s\n", path, strerror(errno));
		return;
	}

	close(fd);
}

int main(int argc, char *argv[])
{
	struct rpmsg_test_args *targs;

	targs = __get_args(argc, argv);

	switch(targs->type) {
		case RPMSG_PING:
			rpmsg_ping(targs);
			break;
		case RPMSG_SEND:
			rpmsg_send(targs);
			break;
		case RPMSG_RECV:
			rpmsg_recv(targs);
			break;
		default:
			__print_usage();
			break;
	}
}
