#ifndef _RPMSG_CLIENT_H
#define _RPMSG_CLIENT_H

#include <linux/types.h>
#include <asm/msr.h>
#include <linux/rpmsg.h>

/*
 * On BSP/HOST rpmsg_client never announce the driver ept address, it
 * dynamically allocate ept address from RPMSG_RESERVED_ADDRESSES range.
 * As, 1024 is the first outside the RPMSG_RESERVED_ADDRESSES range,
 * it is the one which RPMSG virtio diriver picks up, hence hard coding
 * the bsp_addr as 1024. Dirty hack to use the same client dirver on AP & BSP
 */

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

typedef void (*rpmsg_ping_cb_t)(struct rpmsg_client_vdev *, void *, int, u32);
struct rpmsg_client_vdev {
	u32 src;
	u32 dst;
	int flags;
	void *priv;
	struct rpmsg_client_device *rcdev;
	struct rpmsg_endpoint *ept;
	struct recv_queue rvq;
	wait_queue_head_t client_wait;
	rpmsg_ping_cb_t ping_cb;
	struct rpmsg_client_stats gstats;
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
#endif //_RPMSG_CLIENT_H
