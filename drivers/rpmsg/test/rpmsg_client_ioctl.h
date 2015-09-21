#ifndef _RPMSG_CLIENT_IOCTL_H_
#define _RPMSG_CLIENT_IOCTL_H_
#include <linux/types.h>

#define RPMSG_PING_IOCTL	_IOWR('s', 1, void *)
#define RPMSG_CFG_DEV_IOCTL	_IOWR('s', 2, void *)
#define RPMSG_CREATE_EPT_IOCTL	_IOWR('s', 3, unsigned int)
#define RPMSG_DESTROY_EPT_IOCTL	_IOWR('s', 4, unsigned int)

enum __rpmsg_test_types {
	RPMSG_NULL_TEST,
	RPMSG_PING,
	RPMSG_SEND,
	RPMSG_RECV,
	RPMSG_MAX_TEST
};

struct rpmsg_test_args {
	int flags;
	int remote_cpu;
	int type;
	int num_runs;
	int sbuf_size;
	int rbuf_size;
	int verbose;
	unsigned int src_ept;
	unsigned int dst_ept;
	int wait;
};

#endif //_RPMSG_CLIENT_IOCTL_H_
