#ifndef _RPMSG_CLIENT_IOCTL_H_
#define _RPMSG_CLIENT_IOCTL_H_
#include <linux/types.h>

#define RPMSG_PING_IOCTL	_IOWR('s', 1, void *)
#define RPMSG_CFG_DEV_IOCTL	_IOWR('s', 2, void *)
#define RPMSG_CREATE_EPT_IOCTL	_IOWR('s', 3, unsigned int)
#define RPMSG_DESTROY_EPT_IOCTL	_IOWR('s', 4, unsigned int)
#define RPMSG_READ_STATS_IOCTL	_IOWR('s', 5, void *)

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

#define MAX_TEST_STATE		3

struct rpmsg_client_timestamp {
	unsigned long start_time;
	unsigned long end_time;
};

struct rpmsg_client_stats {
	unsigned int nsend;
	unsigned int nrecv;
	unsigned long bsend;
	unsigned long brecv;
	unsigned long tmin;
	unsigned long tmax;
	unsigned long tavg;
	unsigned long tsum;
	unsigned long triptime;
	struct rpmsg_client_timestamp timestamps[MAX_TEST_STATE];
};

#ifdef __KERNEL__
#define G (*(struct rpmsg_client_stats*)&rvdev->gstats)
#define __print		printk
#else
#define G (*(struct rpmsg_client_stats*)&gstats)
#define __print		printf
#endif

#define nsend		(G.nsend)
#define nrecv		(G.nrecv)
#define bsend		(G.bsend)
#define	brecv		(G.brecv)
#define tmin		(G.tmin)
#define tmax		(G.tmax)
#define tavg		(G.tavg)
#define tsum		(G.tsum)
#define triptime	(G.triptime)
#define send_start_time	(G.timestamps[0].start_time)
#define send_end_time	(G.timestamps[0].end_time)
#define recv_start_time (G.timestamps[1].start_time)
#define recv_end_time	(G.timestamps[1].end_time)
#define test_start_time (G.timestamps[2].start_time)
#define test_end_time	(G.timestamps[2].end_time)

//#define RPMSG_KTIME		1

#define INIT_STATS()	do {	\
	memset(&G, 0, sizeof(struct rpmsg_client_stats));	\
	tmin = UINT_MAX;					\
} while(0)

#ifdef	RPMSG_KTIME
#define LOG_TIME(x)	do {			\
	x = ktime_to_ns(ktime_get_real());	\
} while(0)
#else
#define LOG_TIME(x)	do {			\
	rdtscll(x);				\
} while(0)
#endif

#define UPDATE_ROUND_TRIP_STATS()	do {		\
	t = triptime = recv_end_time - send_start_time;	\
	triptime = triptime/1000;			\
	tsum += triptime;				\
	if(triptime < tmin)				\
		tmin = triptime;			\
	if(triptime > tmax)				\
		tmax = triptime;			\
} while(0)

#define UPDATE_ROUND_TRIP(p, q)	do {			\
	unsigned long t;				\
	t = triptime = ((q) - (p));			\
	triptime = triptime/1000;			\
	tsum += triptime;				\
	if(triptime < tmin)				\
		tmin = triptime;			\
	if(triptime > tmax)				\
		tmax = triptime;			\
} while(0)

typedef unsigned int u32;
#define PRINT_TEST_SUMMARY()	do {			\
	unsigned long totalbytes;			\
	totalbytes = bsend + brecv;			\
	__print("\n--- rpmsg test statistics ---\n"	\
			"%u packets transmitted, "	\
			"%u packets received, "	\
			"%lu bytes transfered, "	\
			"%lu bytes/ms. \n",		\
			nsend, nrecv, totalbytes,	\
			(totalbytes / tsum));		\
	if (tmin != UINT_MAX) {				\
		tavg = tsum / nrecv;			\
		__print("round-trip min/avg/max = "	\
			"%u.%03u/%u.%03u/%u.%03u ms\n",	\
		(u32)tmin / 1000, (u32)tmin % 1000,	\
		(u32)tavg / 1000, (u32)tavg % 1000,	\
		(u32)tmax / 1000, (u32)tmax % 1000);	\
	}						\
} while(0)

#endif //_RPMSG_CLIENT_IOCTL_H_
