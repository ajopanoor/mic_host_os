#ifndef _RPMSG_CLIENT_H
#define _RPMSG_CLIENT_H

#include <linux/types.h>
#include <asm/msr.h>
#include <linux/rpmsg.h>

#define RPMSG_KTIME		1
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

#define G (*(struct rpmsg_client_stats*)&gstats)
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

#define INIT_STATS()	do {	\
	memset(&gstats, 0, sizeof(struct rpmsg_client_stats));	\
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

#define PRINT_TEST_SUMMARY()	do {			\
	unsigned long totalbytes;			\
	totalbytes = bsend + brecv;			\
	tsum = (tsum/1000);				\
	printk("\n--- rpmsg ping statistics ---\n"	\
			"%u packets transmitted, "	\
			"%u packets received, "	\
			"%lu bytes transfered, "	\
			"%lu bytes/ms. \n",		\
			nsend, nrecv, totalbytes,	\
			(totalbytes / tsum));		\
	if (tmin != UINT_MAX) {				\
		tavg = tsum / nrecv;			\
		printk("round-trip min/avg/max = "	\
			"%u.%03u/%u.%03u/%u.%03u ms\n",	\
		(u32)tmin / 1000, (u32)tmin % 1000,	\
		(u32)tavg / 1000, (u32)tavg % 1000,	\
		(u32)tmax / 1000, (u32)tmax % 1000);	\
	}						\
} while(0)

/*
 * On BSP/HOST rpmsg_client never announce the driver ept address, it
 * dynamically allocate ept address from RPMSG_RESERVED_ADDRESSES range.
 * As, 1024 is the first outside the RPMSG_RESERVED_ADDRESSES range,
 * it is the one which RPMSG virtio diriver picks up, hence hard coding
 * the bsp_addr as 1024. Dirty hack to use the same client dirver on AP & BSP
 */

#define LOOP_ADDR		127
#define	BSP_ADDR		1024
#define	DMA_ADDR		3500
#define IOV_ADDR		3501

struct dma_buf_info {
	void *va;
	dma_addr_t da;
	void *priv;
	size_t len;
};

struct recv_queue {
	struct list_head recvqueue;
	spinlock_t recv_spinlock;
	wait_queue_head_t recv_wait;
};

struct rpmsg_client_vdev;
struct rpmsg_client_device {
	int id;
	void *priv;
	struct cdev cdev;
	struct rpmsg_channel *rpdev;
	struct list_head rblk_list;
	spinlock_t rblk_spinlock;
	struct rpmsg_client_vdev *g_rvdev;
	struct dma_buf_info *dma_buf_pool;
	struct dma_buf_info *dma_buf_iov;
};

struct rpmsg_client_vdev {
	u32 src;
	u32 dst;
	int flags;
	void *priv;
	struct rpmsg_client_device *rcdev;
	struct rpmsg_endpoint *ept;
	struct recv_queue rvq;
	wait_queue_head_t client_wait;
};

enum rpmsg_rblk_flags {
	RPMSG_SHM_BUF	= 1,
	RPMSG_DMA_BUF	= 2,
};

struct rpmsg_recv_blk{
	int len;
	void  *priv;
	enum rpmsg_rblk_flags flags;
	unsigned int addr;
	void *data;
	dma_addr_t da;
	struct list_head vlink;
	struct list_head clink;
};

void rpmsg_client_ping(struct rpmsg_client_vdev *rvdev,
		 				struct rpmsg_test_args *targs);
void rpmsg_ping_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src);
void rpmsg_loopback_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src);
int rpmsg_ping_status(struct rpmsg_client_vdev *rvdev);
struct rpmsg_endpoint *rpmsg_client_open_loopback_ept(struct rpmsg_channel *rpdev,
		unsigned long addr);
#endif //_RPMSG_CLIENT_H
