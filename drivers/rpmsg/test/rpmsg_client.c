/*
 * Remote processor messaging - client module for hooking rpmsg to user space.
 *
 * Ajo Jose Panoor <ajo.jose.panoor@huawei.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/vringh.h>
#include <linux/vmalloc.h>
#include "rpmsg_client_ioctl.h"
#include "rpmsg_client.h"
#include "../../misc/mic/host/mic_device.h"
#include "../../misc/mic/host/mic_smpt.h"

#define RPMSG_CLIENT_MAX_NUM_DEVS		256
#define RPMSG_CLIENT_DEV			"crpmsg"
#define MAX_DMA_RBLK_CNT			128
#define DMA_BUF_SIZE				PAGE_ALIGN(64 * 1024ULL)

/* Driver name */
static const char driver_name[] = "rpmsg_client";

/* ID allocator for RPMSG client devices */
static struct ida g_rpmsg_client_ida;

/* Class of RPMSG client devices for sysfs accessibility. */
static struct class *g_rpmsg_client_class;

/* Base device node number for rpmsg client devices */
static dev_t g_rpmsg_client_devno;

static struct rpmsg_client_device *rcdev;

int is_bsp = 1;

struct rpmsg_client_vdev *rpmsg_init_rvdev(struct rpmsg_client_device *rcdev)
{
	struct rpmsg_client_vdev *rvdev;

	rvdev = kzalloc(sizeof(*rvdev), GFP_KERNEL);
	if(!rvdev)
		return NULL;

	rvdev->rcdev = rcdev;
	rvdev->src = rcdev->rpdev->src;
	rvdev->dst = rcdev->rpdev->dst;

	INIT_LIST_HEAD(&rvdev->rvq.recvqueue);
	init_waitqueue_head(&rvdev->rvq.recv_wait);
	spin_lock_init(&rvdev->rvq.recv_spinlock);
	INIT_STATS();

	return rvdev;
}

int rpmsg_open(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev=NULL;
	struct rpmsg_client_device *rcdev = container_of(inode->i_cdev,
			 struct rpmsg_client_device, cdev);

	rvdev = rpmsg_init_rvdev(rcdev);

	BUG_ON(!rvdev);

	f->private_data = rvdev;

	return nonseekable_open(inode, f);
}

static inline void rpmsg_queue(struct rpmsg_recv_blk *rblk,
						 struct list_head *queue)
{
	struct recv_queue *rvq = container_of(queue,
					struct recv_queue, recvqueue);
	unsigned long flags;

	BUG_ON(!rvq);
	BUG_ON(!rblk);
	spin_lock_irqsave(&rvq->recv_spinlock, flags);
	list_add_tail(&rblk->vlink, &rvq->recvqueue);
	spin_unlock_irqrestore(&rvq->recv_spinlock, flags);
}

static inline void put_rblk(struct rpmsg_recv_blk *rblk)
{
	unsigned long flags;

	BUG_ON(!rblk);
	spin_lock_irqsave(&rcdev->rblk_spinlock, flags);
	list_add_tail(&rblk->clink, &rcdev->rblk_list);
	spin_unlock_irqrestore(&rcdev->rblk_spinlock, flags);
}

static inline struct rpmsg_recv_blk* get_rblk(void)
{
	struct rpmsg_recv_blk *rblk = NULL;
	unsigned long flags;

	spin_lock_irqsave(&rcdev->rblk_spinlock, flags);
	if(!list_empty(&rcdev->rblk_list)) {
		rblk = list_first_entry(&rcdev->rblk_list,
				struct rpmsg_recv_blk, clink);
		list_del(&rblk->clink);
	}
	spin_unlock_irqrestore(&rcdev->rblk_spinlock, flags);
	return rblk;
}

static inline struct rpmsg_recv_blk* rpmsg_dequeue(struct list_head *queue)
{
	struct recv_queue *rvq;
	struct rpmsg_client_vdev *rvdev;
	struct rpmsg_recv_blk *rblk = NULL;
	unsigned long flags;

	rvq = container_of(queue, struct recv_queue, recvqueue);
	rvdev = container_of(rvq, struct rpmsg_client_vdev, rvq);
	rcdev = rvdev->rcdev;

	BUG_ON(!rcdev);

	spin_lock_irqsave(&rvq->recv_spinlock, flags);
	if(!list_empty(&rvq->recvqueue)) {
			rblk = list_first_entry(&rvq->recvqueue,
					struct rpmsg_recv_blk, vlink);
			list_del(&rblk->vlink);
	}
	spin_unlock_irqrestore(&rvq->recv_spinlock, flags);
	return rblk;
}

static inline void free_rblks(void)
{
	struct rpmsg_recv_blk *rblk = NULL;
	while((rblk = get_rblk())) {
		kfree(rblk);
	}
}

static int alloc_dma_rblk_pool(struct dma_buf_info *dinfo, int count,
		size_t size)
{
	struct rpmsg_recv_blk *rblk = NULL;
	int i = 0;

	while (i < count) {
		rblk = kmalloc(sizeof(*rblk), GFP_ATOMIC);
		if (!rblk) {
			printk(KERN_ERR "kmalloc failed!\n");
			goto enomem;
		}
		rblk->flags |= RPMSG_DMA_BUF;
		rblk->data = dinfo->va + (i * size);
		rblk->da = (unsigned long int)dinfo->da + (i * size);
		put_rblk(rblk);
		i++;
	}

	return 0;
enomem:
	free_rblks();
	return -ENOMEM;
}

static inline void free_rblk(struct rpmsg_recv_blk *rblk)
{
	BUG_ON(!rblk);

	if (rblk->flags & RPMSG_DMA_BUF)
		put_rblk(rblk);
	else
		kfree(rblk);
}

static void rpmsg_free_rvdev(struct rpmsg_client_vdev *rvdev)
{
	struct recv_queue *rvq = &rvdev->rvq;
	struct rpmsg_recv_blk *rblk;

	while((rblk = rpmsg_dequeue(&rvq->recvqueue))) {
		free_rblk(rblk);
	}
	return;
}

int rpmsg_release(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;

	rpmsg_free_rvdev(rvdev);

	if(rvdev->ept)
		rpmsg_destroy_ept(rvdev->ept);

	f->private_data = NULL;

	return 0;
}

#define __COPY_TO_USER__(buf, rblk)				\
({								\
 	int  __ret;						\
 	char *__data;						\
	if (rblk->flags & RPMSG_DMA_BUF) {			\
 		__data = rblk->data + sizeof(struct rpmsg_hdr);	\
 		__len = rblk->len - sizeof(struct rpmsg_hdr);	\
	} else {						\
 		__data = rblk->data;				\
		__len = rblk->len;				\
	}							\
	__ret = copy_to_user(buf, __data, __len);		\
 	__ret;							\
})

static ssize_t
rpmsg_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_client_device *rcdev = rvdev->rcdev;
	struct rpmsg_channel *rpdev = rcdev->rpdev;
	struct rpmsg_recv_blk *rblk;
	struct recv_queue *rvq = &rvdev->rvq;
	ssize_t __len;
	int ret;

	rblk = rpmsg_dequeue(&rvq->recvqueue);
	if (!rblk) {
		if (f->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(rvq->recv_wait,
				(rblk = rpmsg_dequeue(&rvq->recvqueue)));
		if (ret)
			return ret;
	}

	dev_dbg(&rpdev->dev, "%s: %d bytes from %u ",__func__,
						rblk->len, rblk->addr);
	if(rblk->len > count) {
		dev_err(&rpdev->dev, "%s: packet too big %d > %zu\n",__func__,
							rblk->len, count);
		free_rblk(rblk);
		return -EMSGSIZE;
	}

	ret = __COPY_TO_USER__(buf, rblk);
	if(ret < 0){
		dev_err(&rpdev->dev, "%s: copy_to_user failed u %p k %p"
				" ret %d len %zu \n", __func__, buf, rblk->data,
				ret, __len);
		free_rblk(rblk);
		return -EFAULT;
	}

	free_rblk(rblk);
	return __len;
}

static struct dma_buf_info * dma_buf_alloc(struct rpmsg_channel *rpdev, int len)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);
	struct dma_buf_info *dinfo;

	dinfo = kmalloc(sizeof(*dinfo), GFP_ATOMIC);
	if(!dinfo) {
		printk(KERN_ERR "%s failed to allocate dinfo", __func__);
		return NULL;
	}
	dinfo->va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
			get_order(len));
	if(!dinfo->va) {
		printk(KERN_ERR "%s get_free_pages failed", __func__);
		goto free_dma_buf;
	}
	dinfo->da = mic_map_single(mdev, dinfo->va, len);
	if (mic_map_error(dinfo->da)) {
		printk(KERN_ERR "%s mic_map_single failed", __func__);
		goto free_pages;
	}
	dinfo->priv = mdev;
	dinfo->len = len;

	printk(KERN_INFO "alloc dma_buf %p size %d \n", dinfo->va, len);

	return dinfo;

free_pages:
	free_pages((unsigned long)dinfo->va, get_order(len));
free_dma_buf:
	kfree(dinfo);
	return NULL;
}

void dma_buf_free(struct rpmsg_channel *rpdev, struct dma_buf_info *dinfo)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);

	mic_unmap_single(mdev, dinfo->da, dinfo->len);
	free_pages((unsigned long)dinfo->va, get_order(dinfo->len));
	kfree(dinfo);
}

static ssize_t
__rpmsg_write(struct rpmsg_client_vdev *rvdev, const char __user *buf, size_t count)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	int buf_0 = ((int __user *)buf)[0];
	int ret = -EINVAL;

	if (count > DMA_BUF_SIZE)
		return 0;

	LOG_TIME(send_start_time);

	if (rvdev->flags & O_NONBLOCK) {
		ret = rpmsg_trysend_offchannel(rpdev, rvdev->src, rvdev->dst,
				(void *)buf, (int)count);
	} else {
		ret = rpmsg_send_offchannel(rpdev, rvdev->src, rvdev->dst,
				(void *)buf, (int)count);
	}
	if(ret < 0)
		goto write_fail;

	LOG_TIME(send_end_time);

	nsend++;
	bsend += count;
	UPDATE_RTT(send_start_time, send_end_time, tsum, tmin, tmax, rx_rtt);
	dev_dbg(&rpdev->dev,"%s Flag %x Tx Buf[0] %d \n", __func__,
			rvdev->flags, buf_0);

	return count;

write_fail:
	dev_err(&rpdev->dev,"%s Flag %x Tx Buf[0] %d \n", __func__,
			rvdev->flags, buf_0);
	return 0;
}

static ssize_t
rpmsg_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;

	return __rpmsg_write(rvdev, buf, count);
}

void rpmsg_client_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct rpmsg_recv_blk *rblk;
	struct rpmsg_client_vdev *rvdev = priv;

	LOG_TIME(recv_start_time);
	nrecv++;
	brecv += len;

	rblk = kmalloc(sizeof(*rblk), GFP_ATOMIC);
	if (!rblk) {
		dev_err(&rpdev->dev, "kmalloc failed!\n");
		return;
	}

	BUG_ON(!rvdev);

	rblk->addr = src;
	rblk->priv = priv;
	rblk->len = len;
	rblk->flags &= ~RPMSG_DMA_BUF;
	rblk->data = data;

	LOG_TIME(recv_end_time);
	UPDATE_RTT(recv_start_time, recv_end_time, rsum, rmin, rmax, rx_rtt);

	dev_info(&rpdev->dev, "%s Received %d bytes from 0x%x\n",
			__func__, len, src);
	free_rblk(rblk);
}

void rpmsg_ept_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct rpmsg_recv_blk *rblk;
	struct rpmsg_client_vdev *rvdev = priv;

	LOG_TIME(recv_start_time);

	rblk = kmalloc(sizeof(*rblk), GFP_ATOMIC);
	if (!rblk) {
		dev_err(&rpdev->dev, "kmalloc failed!\n");
		return;
	}

	BUG_ON(!rvdev);

	rblk->addr = src;
	rblk->priv = priv;
	rblk->len = len;
	rblk->flags &= ~RPMSG_DMA_BUF;
	rblk->data = data;

	dev_dbg(&rpdev->dev, "%s: %d bytes from 0x%x [%4d]",__func__, len,
						src, ((int *)data)[0]);
	if(rvdev->ping_cb) {
		rvdev->ping_cb(rvdev, rblk->data, rblk->len, src);
		free_rblk(rblk);
	} else {
		rpmsg_queue(rblk, &rvdev->rvq.recvqueue);
		wake_up_interruptible(&rvdev->rvq.recv_wait);
	}

	nrecv++;
	brecv += len;
	LOG_TIME(recv_end_time);
	UPDATE_RTT(recv_start_time, recv_end_time, rsum, rmin, rmax, rx_rtt);
}

static int __sync_dma(struct mic_device *mdev, dma_addr_t dst, dma_addr_t src,
		size_t len)
{
	int err = 0;
	struct dma_async_tx_descriptor *tx;
	struct dma_chan *mic_ch = mdev->dma_ch[1];

	if (!mic_ch) {
		err = -EBUSY;
		goto error;
	}

	tx = mic_ch->device->device_prep_dma_memcpy(mic_ch, dst, src, len,
						    DMA_PREP_FENCE);
	if (!tx) {
		err = -ENOMEM;
		goto error;
	} else {
		dma_cookie_t cookie = tx->tx_submit(tx);

		err = dma_submit_error(cookie);
		if (err)
			goto error;
		err = dma_sync_wait(mic_ch, cookie);
	}
error:
	if (err)
		printk(KERN_ERR "%s %d err %d\n", __func__, __LINE__, err);
	return err;
}

#define __SYNC_DMA(mdev, da, daddr, iovlen, dma)		\
({								\
 	int  __ret = 0;						\
 	if (dma) {						\
		__ret = __sync_dma(mdev, da, daddr, iovlen);	\
	} else {						\
		void __iomem *dbuf = mdev->aper.va + daddr;	\
		memcpy(va, dbuf, iovlen);			\
	}							\
	__ret;							\
})

static int __vringh_copy2(struct mic_device *mdev, struct vringh_kiov *iov,
		struct dma_buf_info *dinfo, size_t len, size_t *out_len, bool dma)
{
	int err = 0;
	size_t iovlen, tot_len = 0;
	dma_addr_t daddr, da;
	void *va;

	va = dinfo->va;
	da = dinfo->da;
	while (len && iov->i < iov->used) {
		iovlen = iov->iov[iov->i].iov_len;
		daddr = (dma_addr_t)iov->iov[iov->i].iov_base;
		err = __SYNC_DMA(mdev, da, daddr, iovlen, dma);
		if(err) {
			printk(KERN_ERR "%s %d DMA sync failed %llx len %zu"
				" fallback to memcpy\n", __func__, __LINE__,
				(u64)daddr, iovlen);
			(void)__SYNC_DMA(mdev, da, daddr, iovlen, false);
		}
		len -= iovlen;
		va += iovlen;
		da += iovlen;
		tot_len += iovlen;
		++iov->i;
	}
	*out_len = tot_len;
	return err;
}

void rpmsg_iov_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);
	struct rpmsg_client_vdev *rvdev = priv;
	struct dma_buf_info *dinfo = rcdev->dma_buf_iov;
	bool dma = (rvdev->flags & O_SYNC);
	struct vringh_kiov *riov = data;
	size_t count;
	int ret;

	LOG_TIME(recv_start_time);

	BUG_ON(!dinfo);
	BUG_ON(!rvdev);

	ret = __vringh_copy2(mdev, riov, dinfo, dinfo->len, &count, dma);
	if(ret)
		dev_err(&rpdev->dev, "%s DMA failed\n",__func__);

	dev_dbg(&rpdev->dev, "%s %zu bytes of %d sized buffer from ept %d\n",
			(dma ? "dma-ed" : "memcpy-ed"), count, len, src);

	if(rvdev->ping_cb)
		rvdev->ping_cb(rvdev, dinfo->va, count, src);

	nrecv++;
	brecv += count;
	LOG_TIME(recv_end_time);
	UPDATE_RTT(recv_start_time, recv_end_time, rsum, rmin, rmax, rx_rtt);
}

void rpmsg_dma_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);
	struct rpmsg_client_vdev *rvdev = priv;
	struct rpmsg_recv_blk *rblk;
	dma_addr_t src_addr = (dma_addr_t)data;
	int err;

	LOG_TIME(recv_start_time);

	rblk = get_rblk();

	BUG_ON(!rvdev);
	BUG_ON(!rblk);
	BUG_ON(!priv);
	BUG_ON(len > PAGE_SIZE);

	rblk->addr = src;
	rblk->priv = priv;
	rblk->len = len;

	err = __sync_dma(mdev, rblk->da, src_addr, len);
	if(err) {
		void __iomem *dbuf = mdev->aper.va + src_addr;
		dev_err(&rpdev->dev, "%s DMA sync failed,fallback to memcpy\n",
				__func__);
		memcpy(rblk->data, dbuf, len);
	} else
		dev_dbg(&rpdev->dev, "%s: DMAed %u bytes from 0x%x", __func__,
				len, src);

	nrecv++;
	brecv += len;

	LOG_TIME(recv_end_time);
	UPDATE_RTT(recv_start_time, recv_end_time, rsum, rmin, rmax, rx_rtt);

	if(rvdev->ping_cb) {
		rvdev->ping_cb(rvdev, rblk->data, rblk->len, src);
		free_rblk(rblk);
	} else {
		rpmsg_queue(rblk, &rvdev->rvq.recvqueue);
		wake_up_interruptible(&rvdev->rvq.recv_wait);
	}
}

static struct rpmsg_test_args *copy_args_from_user(unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct rpmsg_test_args *kargs = NULL;

	kargs = kmalloc(sizeof(*kargs), GFP_KERNEL);
	if (!kargs)
		return NULL;

	if (copy_from_user(kargs, argp, sizeof(*kargs))) {
		kfree(kargs);
		return NULL;
	}
	return kargs;
}

static void dump_args(struct rpmsg_test_args *targs)
{
	printk(KERN_INFO "c=%d t=%d n=%d s=%zu r=%zu e=%d d=%d w=%d flags=%x\n",
			targs->remote_cpu, targs->type,
			targs->num_runs, targs->sbuf_size,
			targs->rbuf_size, targs->src_ept,
		        targs->dst_ept, targs->wait, targs->flags);
}

static void rpmsg_cfg_client_dev(struct rpmsg_client_vdev *rvdev,
					struct rpmsg_test_args *kargs)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;

	if (kargs->dst_ept && (kargs->dst_ept != rvdev->dst)) {
		dev_info(&rpdev->dev, "%s cfg ept_dst %d\n", __func__,
				kargs->dst_ept);
		rvdev->dst = kargs->dst_ept;
	}
	if (kargs->flags & O_SYNC) {
		dev_info(&rpdev->dev, "%s cfg mem-copy rx\n", __func__);
		rvdev->flags |= O_SYNC;
	}
}

static int rpmsg_read_vdev_stats(struct rpmsg_client_vdev *rvdev,
		unsigned long arg)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	int size = sizeof(struct rpmsg_client_stats);
	char __user *buf = (char __user *)arg;
	int ret = 0;

	ret = access_ok(VERIFY_WRITE, buf, size);
	if (ret < 0) {
		dev_err(&rpdev->dev, "access_ok failed %s %d", __func__, ret);
		return ret;
	}
	ret = copy_to_user(buf, &rvdev->gstats, size);
	if (ret < 0)
		dev_err(&rpdev->dev, "failed to copy rpmsg_client_stats\n");

	return ret;
}

static inline rpmsg_rx_cb_t get_cb(struct rpmsg_client_device *rcdev, u32 addr)
{
	rpmsg_rx_cb_t cb;

	switch (addr) {
		case DMA_ADDR:
			cb = rpmsg_dma_cb;
			break;
		case IOV_ADDR:
			cb = rpmsg_iov_cb;
			break;
		default:
			cb = rpmsg_ept_cb;
			break;
	}
	return cb;
}

static int create_ept(struct rpmsg_client_vdev *rvdev, unsigned long arg)
{
	struct rpmsg_client_device *rcdev = rvdev->rcdev;
	struct rpmsg_channel *rpdev = rcdev->rpdev;
	struct rpmsg_endpoint *ept;
	u32 addr = (u32)arg;
	rpmsg_rx_cb_t cb;
	int ret = 0;

	cb = get_cb(rcdev, addr);

	ept = rpmsg_create_ept(rpdev, cb, rvdev, addr);
	if (!ept) {
		dev_err(&rpdev->dev, "failed to create ept\n");
		return ret;
	}

	rvdev->src = addr;
	rvdev->ept = ept;
	return ret;
}

static void delete_ept(struct rpmsg_client_vdev *rvdev, unsigned long arg)
{
	unsigned int addr = arg;

	BUG_ON(addr != rvdev->src);

	rpmsg_destroy_ept(rvdev->ept);

	rvdev->src = 0;
	rvdev->ept = NULL;
}

static void ping_tx_worker(struct rpmsg_client_vdev *rvdev, void *data, int len,
		u32 src)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	struct rpmsg_test_args *kargs = rvdev->priv;
	int seq, i, ept = rvdev->src;

	LOG_TIME(ping_end_time);
	UPDATE_RTT(ping_start_time, ping_end_time, rtsum, rtmin, rtmax, triptime);

	if (!kargs->num_runs) {
		kargs->ping_done = 1;
		wake_up_interruptible(&rvdev->client_wait);
		return;
	}

	LOG_TIME(ping_start_time);

	i = (ept == DMA_ADDR || ept == IOV_ADDR) ? 4 : 0;

	seq = ((u32 *)data)[i];
	((int *)kargs->sbuf)[0] = ++seq;

	dev_dbg(&rpdev->dev, "%s to %u seq [%d]\n", __func__, src, seq);

	(void)__rpmsg_write(rvdev, kargs->sbuf, kargs->sbuf_size);

	kargs->num_runs--;
}

#define PING_RX_BUF_SIZE	64
static void ping_rx_worker(struct rpmsg_client_vdev *rvdev, void *data, int len,
		u32 src)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	struct rpmsg_test_args *kargs = rvdev->priv;
	int seq, i, ept = rvdev->src;

	i = (ept == DMA_ADDR || ept == IOV_ADDR) ? 4 : 0;

	seq = ((int *)kargs->rbuf)[0] = ((u32 *)data)[i];

	dev_dbg(&rpdev->dev, "%s to %d seq [%d]\n", __func__, src, seq);

	(void)__rpmsg_write(rvdev, kargs->rbuf, kargs->rbuf_size);

	kargs->num_runs--;

	if (!kargs->num_runs) {
		kargs->ping_done = 1;
		wake_up_interruptible(&rvdev->client_wait);
		return;
	}
}

static int rpmsg_ping_send(struct rpmsg_client_vdev *rvdev,
		struct rpmsg_test_args *kargs)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	u32 *payload;
	int ret = 0, seq = 1;

	LOG_TIME(ping_start_time);
	kargs->sbuf = vmalloc(kargs->sbuf_size);
	if (IS_ERR(kargs->sbuf)) {
		ret = PTR_ERR(kargs->sbuf);
		dev_err(&rpdev->dev, "copy from user failed \n");
		return ret;
	}
	rvdev->ping_cb = ping_tx_worker;
	ret = create_ept(rvdev, kargs->src_ept);
	if(ret)
		return ret;
	payload = (u32 *) kargs->sbuf;
	payload[0] = seq;

	dev_dbg(&rpdev->dev, "%s to %d seq [%d]\n", __func__, rvdev->dst, seq);

	(void)__rpmsg_write(rvdev, kargs->sbuf, kargs->sbuf_size);

	kargs->num_runs--;

	return ret;
}

static int rpmsg_ping_recv(struct rpmsg_client_vdev *rvdev,
		struct rpmsg_test_args *kargs)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	int ret = 0;

	kargs->rbuf = vmalloc(PING_RX_BUF_SIZE);
	if (IS_ERR(kargs->rbuf)) {
		ret = PTR_ERR(kargs->rbuf);
		dev_err(&rpdev->dev, "copy from user failed \n");
		return ret;
	}
	kargs->rbuf_size = PING_RX_BUF_SIZE;
	rvdev->ping_cb = ping_rx_worker;
	ret = create_ept(rvdev, kargs->src_ept);
	return ret;
}

static inline void rpmsg_free_ping_rsc(struct rpmsg_client_vdev *rvdev,
		struct rpmsg_test_args *kargs)
{
	if(kargs->sbuf)
		vfree(kargs->sbuf);
	if(kargs->rbuf)
		vfree(kargs->rbuf);

	rvdev->ping_cb = NULL;
	rvdev->priv = NULL;
	kargs->sbuf =NULL;
       	kargs->rbuf = NULL;
}

static int rpmsg_ping(struct rpmsg_client_vdev *rvdev, unsigned long arg)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	struct rpmsg_test_args *kargs = NULL;
	int ret = 0;

	kargs = copy_args_from_user(arg);
	if (IS_ERR(kargs)) {
		ret = PTR_ERR(kargs);
		dev_err(&rpdev->dev, "copy from user failed \n");
		return ret;
	}

	dump_args(kargs);
	BUG_ON(rvdev->ping_cb);
	BUG_ON(kargs->ping_done);
	BUG_ON(kargs->sbuf);
	BUG_ON(kargs->rbuf);

	rvdev->priv = kargs;
	rpmsg_cfg_client_dev(rvdev, kargs);
	init_waitqueue_head(&rvdev->client_wait);

	switch (kargs->type) {
		case RPMSG_PING_RECV:
			ret = rpmsg_ping_recv(rvdev, kargs);
			if(ret)
				goto cleanup_rsc;
			break;
		case RPMSG_PING_SEND:
			ret = rpmsg_ping_send(rvdev, kargs);
			if(ret)
				goto cleanup_rsc;
			break;
		default:
			dev_err(&rpdev->dev, "%s ping type unknown %d\n",
					__func__, kargs->type);
			ret = -ENOIOCTLCMD;
			goto free_kargs;
	}
	ret = wait_event_interruptible(rvdev->client_wait, (kargs->ping_done));
	if (ret) {
		dev_err(&rpdev->dev, "%s err\n", (kargs->type == 1) ?
				"rpmsg_ping_recv": "rpmsg_ping_send");
		goto cleanup_ept;
	}

cleanup_ept:
	delete_ept(rvdev, kargs->src_ept);
cleanup_rsc:
	rpmsg_free_ping_rsc(rvdev, kargs);
free_kargs:
	kfree(kargs);
	return ret;
}

long rpmsg_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	struct rpmsg_test_args *kargs = NULL;
	int ret = 0;

	switch (cmd) {
		case RPMSG_PING_IOCTL:
			ret = rpmsg_ping(rvdev, arg);
			break;
		case RPMSG_CREATE_EPT_IOCTL:
			ret = create_ept(rvdev, arg);
			break;
		case RPMSG_DESTROY_EPT_IOCTL:
			delete_ept(rvdev, arg);
			break;
		case RPMSG_CFG_DEV_IOCTL:
			kargs = copy_args_from_user(arg);
			if (IS_ERR(kargs)) {
				ret = PTR_ERR(kargs);
				dev_err(&rpdev->dev, "copy from user failed \n");
				return ret;
			}
			rpmsg_cfg_client_dev(rvdev, kargs);
			kfree(kargs);
			break;
		case RPMSG_READ_STATS_IOCTL:
			ret = rpmsg_read_vdev_stats(rvdev, arg);
			break;
		default:
			dev_err(&rpdev->dev, "%s ioctl %d failed\n", __func__,
					cmd);
			ret = -ENOIOCTLCMD;
			break;
	}
	return ret;
}

static const struct file_operations rpmsg_client_fops = {
	.open = rpmsg_open,
	.release = rpmsg_release,
	.write = rpmsg_write,
	.read = rpmsg_read,
	.unlocked_ioctl = rpmsg_ioctl,
	.owner = THIS_MODULE,
};

static inline void rpmsg_init_rblks(struct rpmsg_client_device *rcdev)
{
	struct rpmsg_channel *rpdev = rcdev->rpdev;
	struct dma_buf_info *dma_buf;

	dma_buf = dma_buf_alloc(rpdev, (MAX_DMA_RBLK_CNT * PAGE_SIZE));
	if(!dma_buf)
		return;

	if(alloc_dma_rblk_pool(dma_buf, MAX_DMA_RBLK_CNT, PAGE_SIZE)) {
		 printk(KERN_ERR "dma buffer alloc failed\n");
		goto free_dma_buf;
	}
	rcdev->dma_buf_pool = dma_buf;
	return;

free_dma_buf:
	dma_buf_free(rpdev, dma_buf);
}

static int rpmsg_client_probe(struct rpmsg_channel *rpdev)
{
	struct device *device = NULL;
	dev_t devno;
	int ret = 0;

	 if(!is_bsp)
		 rpdev->dst = BSP_ADDR;

	rcdev = kzalloc(sizeof(*rcdev), GFP_KERNEL);
	if (IS_ERR(rcdev)) {
		ret = PTR_ERR(rcdev);
		dev_err(&rpdev->dev, "rcdev kmalloc failed %d\n",ret);
		return ret;
	}

	rcdev->id = ida_simple_get(&g_rpmsg_client_ida, 0,
		       		RPMSG_CLIENT_MAX_NUM_DEVS, GFP_KERNEL);
	if (rcdev->id < 0) {
		ret = rcdev->id;
		dev_err(&rpdev->dev, "ida_simple_get failed %d\n", ret);
		goto ida_fail;
	}

	devno = MKDEV(MAJOR(g_rpmsg_client_devno), rcdev->id);

	cdev_init(&rcdev->cdev, &rpmsg_client_fops);

	rcdev->cdev.owner = THIS_MODULE;

	ret = cdev_add(&rcdev->cdev, devno, 1);
	if (ret) {
		dev_err(&rpdev->dev, "cdev_add err id %d ret %d\n",
								rcdev->id, ret);
		goto cdevice_init_fail;
	}

	device = device_create(g_rpmsg_client_class, NULL, devno, NULL,
			 RPMSG_CLIENT_DEV "%d", rcdev->id);
	if (IS_ERR(device)) {
		ret = PTR_ERR(device);
		dev_err(&rpdev->dev, "devce_create failed with %d while trying"
				"to create %s%d", ret, RPMSG_CLIENT_DEV,
				rcdev->id);
		goto cdevice_create_fail;
	}

	rcdev->rpdev = rpdev;

	INIT_LIST_HEAD(&rcdev->rblk_list);
	spin_lock_init(&rcdev->rblk_spinlock);

	rcdev->g_rvdev = rpmsg_init_rvdev(rcdev);
	if(rcdev->g_rvdev < 0)
		goto vdev_create_fail;

	/*
	 * Since the ept is already created for client driver without passing
	 * ept->priv, adding this hack to get the g_rvdev during receive cb
	 */
	rpdev->ept->priv = rcdev->g_rvdev;

	rpmsg_init_rblks(rcdev);
	BUG_ON(!rcdev->dma_buf_pool);

	rcdev->dma_buf_iov  = dma_buf_alloc(rpdev, DMA_BUF_SIZE);
	BUG_ON(!rcdev->dma_buf_iov);

	dev_info(&rpdev->dev, "%s /dev/%s%d (%d:%d) src 0x%x dst 0x%x\n",
			rpdev->id.name, RPMSG_CLIENT_DEV, rcdev->id,
			MAJOR(devno),MINOR(devno), rpdev->src, rpdev->dst);
	return ret;

vdev_create_fail:
	device_destroy(g_rpmsg_client_class, devno);
cdevice_create_fail:
	cdev_del(&rcdev->cdev);
cdevice_init_fail:
	ida_simple_remove(&g_rpmsg_client_ida, rcdev->id);
ida_fail:
	kfree(rcdev);
	return ret;
}

static void rpmsg_client_remove(struct rpmsg_channel *rpdev)
{

	dev_info(&rpdev->dev, "rpmsg client driver is removed\n");

	rpmsg_free_rvdev(rcdev->g_rvdev);
	free_rblks();

	dma_buf_free(rpdev, rcdev->dma_buf_pool);
	dma_buf_free(rpdev, rcdev->dma_buf_iov);

	device_destroy(g_rpmsg_client_class, MKDEV(MAJOR(g_rpmsg_client_devno),
				rcdev->id));
	cdev_del(&rcdev->cdev);
	ida_simple_remove(&g_rpmsg_client_ida, rcdev->id);
	kfree(rcdev);
}

static struct rpmsg_device_id rpmsg_client_driver_id_table[] = {
	{ .name	= "lproc" },
	{ .name	= "mic_proc" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_client_driver_id_table);

static struct rpmsg_driver rpmsg_client = {
	.drv.name	= KBUILD_MODNAME,
	.drv.owner	= THIS_MODULE,
	.id_table	= rpmsg_client_driver_id_table,
	.probe		= rpmsg_client_probe,
	.callback	= rpmsg_client_cb,
	.remove		= rpmsg_client_remove,
};

static int __init rpmsg_client_init(void)
{
	int ret = 0;

	ret = alloc_chrdev_region(&g_rpmsg_client_devno, 0,
		RPMSG_CLIENT_MAX_NUM_DEVS, driver_name);
	if (ret) {
		printk(KERN_ERR "alloc_chrdev_region failed ret %d\n", ret);
		return ret;
	}
	g_rpmsg_client_class = class_create(THIS_MODULE, driver_name);
	if (IS_ERR(g_rpmsg_client_class)) {
		ret = PTR_ERR(g_rpmsg_client_class);
		printk(KERN_ERR "class_create failed ret %d\n", ret);
		goto cleanup_chrdev;
	}
	ida_init(&g_rpmsg_client_ida);
	ret = register_rpmsg_driver(&rpmsg_client);
	if(ret) {
		 printk(KERN_ERR "register_rpmsg_driver failed %d\n",ret);
		 goto cleanup_class;
	}
	return ret;

cleanup_class:
	class_destroy(g_rpmsg_client_class);
cleanup_chrdev:
	unregister_chrdev_region(g_rpmsg_client_devno,
						RPMSG_CLIENT_MAX_NUM_DEVS);
	return ret;
}
module_init(rpmsg_client_init);

static void __exit rpmsg_client_fini(void)
{
	class_destroy(g_rpmsg_client_class);
	unregister_chrdev_region(g_rpmsg_client_devno,
						RPMSG_CLIENT_MAX_NUM_DEVS);
	unregister_rpmsg_driver(&rpmsg_client);
}
module_exit(rpmsg_client_fini);

MODULE_DESCRIPTION("Remote processor messaging client driver");
MODULE_LICENSE("GPL v2");
