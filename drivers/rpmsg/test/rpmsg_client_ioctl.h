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
	RPMSG_PING_RECV,
	RPMSG_PING_SEND,
	RPMSG_SEND,
	RPMSG_RECV,
	RPMSG_MAX_TEST
};

struct rpmsg_test_args {
	int flags;
	int remote_cpu;
	int type;
	int num_runs;
	size_t sbuf_size;
	size_t rbuf_size;
	int verbose;
	unsigned int src_ept;
	unsigned int dst_ept;
	int wait;
	void *sbuf;
	void *rbuf;
	int ping_done;
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
	unsigned long tx_rtt;
	unsigned long rmin;
	unsigned long rmax;
	unsigned long ravg;
	unsigned long rsum;
	unsigned long rx_rtt;
	unsigned long rtmin;
	unsigned long rtmax;
	unsigned long rtavg;
	unsigned long rtsum;
	unsigned long triptime;	// remove when cleaning up old ping code
	struct rpmsg_client_timestamp timestamps[MAX_TEST_STATE];
};

#ifdef __KERNEL__
#define RPMSG_KTIME		1
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
#define tx_rtt		(G.tx_rtt)
#define rmin		(G.rmin)
#define rmax		(G.rmax)
#define ravg		(G.ravg)
#define rsum		(G.rsum)
#define rx_rtt		(G.rx_rtt)
#define rtmin		(G.rtmin)
#define rtmax		(G.rtmax)
#define rtavg		(G.rtavg)
#define rtsum		(G.rtsum)
#define triptime	(G.triptime)
#define send_start_time	(G.timestamps[0].start_time)
#define send_end_time	(G.timestamps[0].end_time)
#define recv_start_time (G.timestamps[1].start_time)
#define recv_end_time	(G.timestamps[1].end_time)
#define ping_start_time (G.timestamps[2].start_time)
#define ping_end_time	(G.timestamps[2].end_time)

#define INIT_STATS()	do {	\
	memset(&G, 0, sizeof(struct rpmsg_client_stats));	\
	tmin = UINT_MAX;					\
	rmin = UINT_MAX;					\
	rtmin = UINT_MAX;					\
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

#define UPDATE_RTT(p, q, sum, min, max, rtt) do {	\
	(rtt) = ((q) - (p));				\
	(sum) += (rtt);					\
	if((rtt) < (min))				\
		(min) = (rtt);				\
	if((rtt) > (max))				\
		(max) = (rtt);				\
} while(0)

typedef unsigned int u32;
#define PRINT_TEST_SUMMARY()	do {			\
	unsigned long totalbytes;			\
	totalbytes = (bsend + brecv);			\
	__print("\n--- rpmsg statistics ---\n"		\
			"%u packets transmitted, "	\
			"%u packets received, "		\
			"%lu bytes transfered\n",	\
			nsend, nrecv, totalbytes);	\
	if (rmin != UINT_MAX) {				\
		ravg = (rsum / nrecv);			\
		__print("rx-time min/avg/max = "	\
			"%u.%03u/%u.%03u/%u.%03u us\n",	\
		(u32)rmin / 1000, (u32)rmin % 1000,	\
		(u32)ravg / 1000, (u32)ravg % 1000,	\
		(u32)rmax / 1000, (u32)rmax % 1000);	\
	}						\
	if (tmin != UINT_MAX) {				\
		tavg = (tsum / nsend);			\
		__print("tx-time min/avg/max = "	\
			"%u.%03u/%u.%03u/%u.%03u us\n",	\
		(u32)tmin / 1000, (u32)tmin % 1000,	\
		(u32)tavg / 1000, (u32)tavg % 1000,	\
		(u32)tmax / 1000, (u32)tmax % 1000);	\
	}						\
	if (rtmin != UINT_MAX) {			\
		rtavg = (rtsum / (nsend + nrecv));	\
		__print("round-trip-time min/avg/max = "\
			"%u.%03u/%u.%03u/%u.%03u us\n",	\
		(u32)rtmin / 1000, (u32)rtmin % 1000,	\
		(u32)rtavg / 1000, (u32)rtavg % 1000,	\
		(u32)rtmax / 1000, (u32)rtmax % 1000);	\
	}						\
} while(0)

#endif //_RPMSG_CLIENT_IOCTL_H_
