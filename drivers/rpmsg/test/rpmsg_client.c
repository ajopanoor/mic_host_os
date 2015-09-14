/*
 * Remote processor messaging - client module for hooking rpmsg to user space.
 *
 * Ajo Jose Panoor <ajo.jose.panoor@huawai.com>
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
#include "rpmsg_client_ioctl.h"
#include "rpmsg_client.h"
#include "../../misc/mic/host/mic_device.h"
#include "../../misc/mic/host/mic_smpt.h"

#define RPMSG_CLIENT_MAX_NUM_DEVS		256
#define RPMSG_CLIENT_DEV			"crpmsg"
#define MAX_DMA_RBLK_CNT			128
#define RPMSG_DMA				1
#define RPMSG_IOV_DMA				0
#define HOST					1
#define DMA_BUF_SIZE				PAGE_ALIGN(64 * 1024ULL)

/* Driver name */
static const char driver_name[] = "rpmsg_client";

/* ID allocator for RPMSG client devices */
static struct ida g_rpmsg_client_ida;

/* Class of RPMSG client devices for sysfs accessibility. */
static struct class *g_rpmsg_client_class;

/* Base device node number for rpmsg client devices */
static dev_t g_rpmsg_client_devno;

/* Global DMA variables */
static struct list_head g_rblk_list;
static spinlock_t g_rblk_spinlock;

struct dma_buf_info {
	void *va;
	dma_addr_t da;
	void *priv;
	size_t len;
};

/* Globals epts */
static struct rpmsg_client_device *rcdev;

static struct rpmsg_endpoint *lb_ept;
static struct rpmsg_endpoint *dma_ept;
static struct rpmsg_endpoint *iov_ept;

/*
 * On BSP/HOST rpmsg_client never announce the driver ept address, it
 * dynamically allocate ept address from RPMSG_RESERVED_ADDRESSES range.
 * As, 1024 is the first outside the RPMSG_RESERVED_ADDRESSES range,
 * it is the one which RPMSG virtio diriver picks up, hence hard coding
 * the bsp_addr as 1024. Dirty hack to use the same client dirver on AP & BSP
 */

/* Static ept addresses */
int loop_addr =  127;
int bsp_addr  = 1024;
int dma_addr  = 3500;
int iov_addr  = 3501;

int is_bsp = 1;

int rpmsg_open(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev;
	struct rpmsg_client_device *rcdev = container_of(inode->i_cdev,
			 struct rpmsg_client_device, cdev);

	rvdev = kzalloc(sizeof(*rvdev), GFP_KERNEL);
	if(!rvdev)
		return -ENOMEM;

	rvdev->rcdev = rcdev;
	rvdev->src = rcdev->rpdev->src;
	rvdev->dst = rcdev->rpdev->dst;
	f->private_data = rvdev;

	return nonseekable_open(inode, f);
}

static inline void rpmsg_queue(struct rpmsg_recv_blk *rblk,
						 struct list_head *queue)
{
	struct rpmsg_client_device *rcdev = container_of(queue,
					struct rpmsg_client_device, recvqueue);
	unsigned long flags;

	BUG_ON(!rcdev);
	BUG_ON(!rblk);
	spin_lock_irqsave(&rcdev->recv_spinlock, flags);
	list_add_tail(&rblk->link, &rcdev->recvqueue);
	spin_unlock_irqrestore(&rcdev->recv_spinlock, flags);
}

static inline void __put_rblk(struct rpmsg_recv_blk *rblk)
{
	unsigned long flags;

	BUG_ON(!rblk);
	spin_lock_irqsave(&g_rblk_spinlock, flags);
	list_add_tail(&rblk->glink, &g_rblk_list);
	spin_unlock_irqrestore(&g_rblk_spinlock, flags);
}

static inline struct rpmsg_recv_blk* __get_rblk(void)
{
	struct rpmsg_recv_blk *rblk = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_rblk_spinlock, flags);
	if(!list_empty(&g_rblk_list)) {
		rblk = list_first_entry(&g_rblk_list,
				struct rpmsg_recv_blk, glink);
		list_del(&rblk->glink);
	}
	spin_unlock_irqrestore(&g_rblk_spinlock, flags);
	return rblk;
}

static inline void __free_rblks(void)
{
	struct rpmsg_recv_blk *rblk = NULL;
	while((rblk = __get_rblk())) {
		kfree(rblk);
	}
}

static int __alloc_dma_rblk_pool(struct dma_buf_info *dinfo, int count,
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
		__put_rblk(rblk);
		i++;
	}

	return 0;
enomem:
	__free_rblks();
	return -ENOMEM;
}

static inline struct rpmsg_recv_blk* rpmsg_dequeue(struct list_head *queue)
{
	struct rpmsg_client_device *rcdev = container_of(queue,
					struct rpmsg_client_device, recvqueue);
	struct rpmsg_recv_blk *rblk = NULL;
	unsigned long flags;

	BUG_ON(!rcdev);
	spin_lock_irqsave(&rcdev->recv_spinlock, flags);
	if(!list_empty(&rcdev->recvqueue)) {
			rblk = list_first_entry(&rcdev->recvqueue,
					struct rpmsg_recv_blk, link);
			list_del(&rblk->link);
	}
	spin_unlock_irqrestore(&rcdev->recv_spinlock, flags);
	return rblk;
}

static inline void __kfree(struct rpmsg_recv_blk *rblk)
{
	BUG_ON(!rblk);

	if (rblk->flags & RPMSG_DMA_BUF)
		__put_rblk(rblk);
	else
		kfree(rblk);
}

static ssize_t
rpmsg_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_client_device *rcdev = rvdev->rcdev;
	struct rpmsg_channel *rpdev = rcdev->rpdev;
	struct rpmsg_recv_blk *rblk;
	int ret, copied;

	rblk = rpmsg_dequeue(&rcdev->recvqueue);
	if (!rblk) {
		if (f->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(rcdev->recv_wait,
				(rblk = rpmsg_dequeue(&rcdev->recvqueue)));
		if (ret)
			return ret;
	}

	dev_info(&rpdev->dev, "%s: %d bytes from %u ",__func__,
						rblk->len, rblk->addr);
	if(rblk->len > count) {
		dev_err(&rpdev->dev, "%s: packet too big %d > %zu\n",__func__,
							rblk->len, count);
		__kfree(rblk);
		return -EMSGSIZE;
	}
	if(copy_to_user(buf, rblk->data, rblk->len)){
		dev_err(&rpdev->dev, "%s: failed to copy usr=%p ker=%p\n",
						__func__, buf, rblk->data);
		__kfree(rblk);
		return -EFAULT;
	}
	copied = rblk->len;
	__kfree(rblk);

	return copied;
}

static struct dma_buf_info * __dma_buf_alloc(struct rpmsg_channel *rpdev, int len)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);
	struct dma_buf_info *dinfo;

	dinfo = kmalloc(sizeof(*dinfo), GFP_ATOMIC);
	if(!dinfo) {
		printk(KERN_ERR "%s failed to allocate dma buffers", __func__);
		return NULL;
	}
	dinfo->va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
			get_order(len));
	if(!dinfo->va) {
		printk(KERN_ERR "%s get_free_pages failed for dma buf", __func__);
		goto free_dma_buf;
	}
#ifdef HOST
	dinfo->da = mic_map_single(mdev, dinfo->va, len);
	if (mic_map_error(dinfo->da)) {
		printk(KERN_ERR "%s mic_map_single failed", __func__);
		goto free_pages;
	}
#else
	dinfo->da = virt_to_phys(dinfo->va);
	if(!dinfo->da)
		goto free_pages;
#endif
	dinfo->priv = mdev;
	dinfo->len = len;

	printk(KERN_INFO "alloc dma_buf %p size %d \n",dinfo->va, len);

	return dinfo;

free_pages:
	free_pages((unsigned long)dinfo->va, get_order(len));
free_dma_buf:
	kfree(dinfo);
	return NULL;
}

void __dma_buf_free(struct rpmsg_channel *rpdev, struct dma_buf_info *dinfo)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);

#ifdef HOST
	mic_unmap_single(mdev, dinfo->da, dinfo->len);
#endif
	free_pages((unsigned long)dinfo->va, get_order(dinfo->len));
	kfree(dinfo);
}

static void __zcopy_free_buf(struct rpmsg_channel *rpdev, void *data, int len,
		void *priv, u32 src)
{
	struct dma_buf_info *sbuf = priv;

	dev_info(&rpdev->dev,"%s src %u data %p priv %p len %d\n", __func__,
			src, data, priv, len);

	__dma_buf_free(rpdev, sbuf);
}

static ssize_t
rpmsg_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	int buf_0 = ((int __user *)buf)[0];
	struct dma_buf_info *sbuf = NULL;
	int ret = -EINVAL;

	if (count > DMA_BUF_SIZE)
		return 0;

	if (rvdev->flags & (O_NONBLOCK|~O_SYNC)) {
		ret = rpmsg_trysend_offchannel(rpdev, rvdev->src, rvdev->dst,
				(void *)buf, (int)count);

	} else if (rvdev->flags & O_SYNC) {
		sbuf = __dma_buf_alloc(rpdev, count);
		if(!sbuf) {
			dev_err(&rpdev->dev, "%s zero-copy tx failed", __func__);
			goto write_fail;
		}
		ret = copy_from_user(sbuf->va, buf, count);
		if(ret) {
			dev_err(&rpdev->dev, "%s copy_from_user failed uptr %p"
				       "kptr %p\n", __func__, buf, sbuf->va);
			__dma_buf_free(rpdev, sbuf);
			goto write_fail;
		}
		ret = rpmsg_send_offchannel_zcopy(rpdev, rvdev->src,
					rvdev->dst, (void *)sbuf->va,
					(int) count, __zcopy_free_buf, sbuf);
	} else {
		ret = rpmsg_send_offchannel(rpdev, rvdev->src, rvdev->dst,
				(void *)buf, (int)count);
	}

write_fail:
	if(ret < 0)
		return 0;

	dev_info(&rpdev->dev,"%s Flag %x Tx Buf[0] %d \n", __func__,
			rvdev->flags, buf_0);
	return count;

}

int rpmsg_release(struct inode *inode, struct file *f)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;

	if(rvdev->ept)
		rpmsg_destroy_ept(rvdev->ept);

	kfree(rvdev);

	f->private_data = NULL;
	return 0;
}

void rpmsg_client_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct rpmsg_recv_blk *rblk;

	dev_info(&rpdev->dev, "%s: %d bytes from 0x%x [%4d]",__func__, len,
						src, ((int *)data)[0]);

	rblk = kmalloc(sizeof(*rblk), GFP_ATOMIC);
	if (!rblk) {
		dev_err(&rpdev->dev, "kmalloc failed!\n");
		return;
	}

	rblk->addr = src;
	rblk->priv = priv;
	rblk->len = len;
	rblk->flags &= ~RPMSG_DMA_BUF;
	rblk->data = data;

	rpmsg_queue(rblk, &rcdev->recvqueue);

	wake_up_interruptible(&rcdev->recv_wait);
}

void rpmsg_ept_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct rpmsg_recv_blk *rblk;

	dev_info(&rpdev->dev, "%s: %d bytes from 0x%x [%4d]",__func__, len,
						src, ((int *)data)[0]);

	rblk = kmalloc(sizeof(*rblk), GFP_ATOMIC);
	if (!rblk) {
		dev_err(&rpdev->dev, "kmalloc failed!\n");
		return;
	}
	rblk->addr = src;
	rblk->priv = priv;
	rblk->len = len;
	rblk->flags &= ~RPMSG_DMA_BUF;
	rblk->data = data;
	rpmsg_queue(rblk, &rcdev->recvqueue);
	wake_up_interruptible(&rcdev->recv_wait);
}

static int __sync_dma(struct mic_device *mdev, dma_addr_t dst, dma_addr_t src,
		size_t len)
{
	int err = 0;
	struct dma_async_tx_descriptor *tx;
	struct dma_chan *mic_ch = mdev->dma_ch[0];

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


static int __rpmsg_copy_to_user(struct mic_device *mdev, struct dma_buf_info *dinfo,
				   size_t len, u64 daddr, size_t dlen)
{
	void __iomem *dbuf = mdev->aper.va + daddr;
	size_t dma_alignment = 1 << mdev->dma_ch[0]->device->copy_align;
	size_t dma_offset;
	size_t partlen;
	int err;

	dma_offset = daddr - round_down(daddr, dma_alignment);
	daddr -= dma_offset;
	len += dma_offset;

	while (len) {
		partlen = min_t(size_t, len, DMA_BUF_SIZE);

		err = __sync_dma(mdev, dinfo->da, daddr,
				   ALIGN(partlen, dma_alignment));
		if (err)
			goto err;

		daddr += partlen;
		dbuf += partlen;
		len -= partlen;
		dma_offset = 0;
	}
	return 0;
err:
	printk(KERN_ERR "%s %d err %d\n", __func__, __LINE__, err);
	return err;
}

static int __vringh_copy(struct mic_device *mdev, struct vringh_kiov *iov,
		struct dma_buf_info *dinfo, size_t len, size_t *out_len)
{
	int ret = 0;
	size_t partlen, tot_len = 0;

	while (len && iov->i < iov->used) {
		partlen = min(iov->iov[iov->i].iov_len, len);
		ret = __rpmsg_copy_to_user(mdev, dinfo, partlen,
						(u64)iov->iov[iov->i].iov_base,
						iov->iov[iov->i].iov_len);
		if (ret) {
			printk(KERN_ERR "%s %d err %d\n", __func__, __LINE__, ret);
			break;
		}
		len -= partlen;
		dinfo->va += partlen;
		tot_len += partlen;
		iov->consumed += partlen;
		iov->iov[iov->i].iov_len -= partlen;
		iov->iov[iov->i].iov_base += partlen;
		if (!iov->iov[iov->i].iov_len) {
			/* Fix up old iov element then increment. */
			iov->iov[iov->i].iov_len = iov->consumed;
			iov->iov[iov->i].iov_base -= iov->consumed;
			iov->consumed = 0;
			iov->i++;
		}
	}
	*out_len = tot_len;
	return ret;
}

void rpmsg_iov_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);
	struct dma_buf_info *dinfo = priv;
	struct vringh_kiov *riov = data;
	size_t count;
	int ret;

	ret = __vringh_copy(mdev, riov, dinfo, dinfo->len, &count);
	if(ret)
		dev_err(&rpdev->dev, "%s DMA failed\n",__func__);

	dev_info(&rpdev->dev, "%s: DMA-ed %uz bytes of %d sized buffer from"
			"0x%x", __func__, count, len, src);
}

void rpmsg_dma_cb(struct rpmsg_channel *rpdev, void *data, int len,
						void *priv, u32 src)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);
	struct rpmsg_recv_blk *rblk;
	dma_addr_t src_addr = data;
	int err;

	dev_info(&rpdev->dev, "%s: %d bytes from 0x%x data 0x%x",__func__, len,
			src, data);
	rblk = __get_rblk();

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
	}

	rpmsg_queue(rblk, &rcdev->recvqueue);
	wake_up_interruptible(&rcdev->recv_wait);
}

static int __copy_args_from_user(struct rpmsg_test_args **__ktargs, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	*__ktargs = kmalloc(sizeof(*__ktargs), GFP_KERNEL);
	if (!__ktargs)
		return -ENOMEM;

	if (copy_from_user((*__ktargs), argp, sizeof(struct rpmsg_test_args))) {
		kfree(*__ktargs);
		return -EINVAL;
	}

	return 0;
}

static void __dump_args(struct rpmsg_test_args *targs)
{
	printk(KERN_INFO "args: c=%d, t=%d, n=%d, s=%d, r=%d, e=%d d=%d w=%d flags=%x\n",
			targs->remote_cpu, targs->type,
			targs->num_runs, targs->sbuf_size,
			targs->rbuf_size, targs->src_ept,
		        targs->dst_ept, targs->wait, targs->flags);
}

static void rpmsg_cfg_client_dev(struct rpmsg_client_vdev *rvdev, unsigned long arg)
{
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	struct rpmsg_test_args *__ktargs = NULL;
	int ret;

	ret = __copy_args_from_user(&__ktargs, arg);
	if(ret) {
		dev_err(&rpdev->dev, "%s __copy_args_from_user failed\n",
				__func__);
		return;
	}
	if (__ktargs->dst_ept && (__ktargs->dst_ept != rvdev->dst)) {
		dev_info(&rpdev->dev, "%s cfg ept_dst %d\n", __func__,
				__ktargs->dst_ept);
		rvdev->dst = __ktargs->dst_ept;
	}
	if (__ktargs->flags & O_SYNC) {
		dev_info(&rpdev->dev, "%s cfg zero-copy tx\n", __func__);
		rvdev->flags |= O_SYNC;
	}
	kfree(__ktargs);
}

long rpmsg_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct rpmsg_client_vdev *rvdev = f->private_data;
	struct rpmsg_channel *rpdev = rvdev->rcdev->rpdev;
	struct rpmsg_test_args *__ktargs = NULL;
	int ret, done;

	switch (cmd) {
		case RPMSG_PING_IOCTL:
		{
			struct rpmsg_endpoint *ept;
			unsigned int addr;
			rpmsg_rx_cb_t cb = rpmsg_ping_cb;

			ret = __copy_args_from_user(&__ktargs, arg);
			if(ret < 0) {
				dev_err(&rpdev->dev, "copy from user failed \n");
				return ret;
			}

			addr = __ktargs->src_ept;

			ept = rpmsg_create_ept(rpdev, cb, rvdev, addr);
			if (!ept) {
				dev_err(&rpdev->dev, "failed to create ept\n");
				return -ENOMEM;
			}

			rvdev->src = addr;
			rvdev->ept = ept;
			ept->priv = rvdev;

			init_waitqueue_head(&rvdev->client_wait);

			rpmsg_client_ping(rvdev, __ktargs);
			if(__ktargs->wait) {
				ret = wait_event_interruptible(rvdev->client_wait,
					(done = rpmsg_ping_status(rvdev)));
				if (ret)
					return ret;
			}

			kfree(__ktargs);
			break;
		}
		case RPMSG_CREATE_EPT_IOCTL:
		{
			struct rpmsg_endpoint *ept;
			unsigned int addr = arg;
			rpmsg_rx_cb_t cb = rpmsg_ept_cb;

			ept = rpmsg_create_ept(rpdev, cb, rvdev, addr);
			if (!ept) {
				dev_err(&rpdev->dev, "failed to create ept\n");
				return -ENOMEM;
			}

			rvdev->src = addr;
			rvdev->ept = ept;

			break;
		}
		case RPMSG_DESTROY_EPT_IOCTL:
		{
			unsigned int addr = arg;

			BUG_ON(addr != rvdev->src);
			rpmsg_destroy_ept(rvdev->ept);
			rvdev->src = 0;
			rvdev->ept = NULL;
			break;
		}
		case RPMSG_CFG_DEV_IOCTL:
		{
			rpmsg_cfg_client_dev(rvdev, arg);
			break;
		}
		default:
			printk(KERN_INFO "%s cmd: %d ioctl failed\n", __func__,
					 cmd);
			return -ENOIOCTLCMD;
	}
	return 0;
}

static const struct file_operations rpmsg_client_fops = {
	.open = rpmsg_open,
	.release = rpmsg_release,
	.write = rpmsg_write,
	.read = rpmsg_read,
	.unlocked_ioctl = rpmsg_ioctl,
	.owner = THIS_MODULE,
};

static inline void __create_dma_ept(struct rpmsg_channel *rpdev)
{
	struct dma_buf_info *dma_pool;

	dma_pool = __dma_buf_alloc(rpdev, (MAX_DMA_RBLK_CNT * PAGE_SIZE));
	if(!dma_pool)
		return;
	if(__alloc_dma_rblk_pool(dma_pool, MAX_DMA_RBLK_CNT, PAGE_SIZE)) {
		 printk(KERN_ERR "dma buffer alloc failed\n");
		goto free_dma_pool;
	}
	dma_ept = rpmsg_create_ept(rpdev, rpmsg_dma_cb, dma_pool, dma_addr);
	if (!dma_ept) {
		dev_err(&rpdev->dev, "dma endpoint create failed\n");
		goto free_rblk;
	}
	return;
free_rblk:
	__free_rblks();
free_dma_pool:
	__dma_buf_free(rpdev, dma_pool);
}

static inline void __create_iov_ept(struct rpmsg_channel *rpdev)
{
	struct dma_buf_info *dma_buf = NULL;

	dma_buf = __dma_buf_alloc(rpdev, DMA_BUF_SIZE);
	if(dma_buf) {
		iov_ept = rpmsg_create_ept(rpdev, rpmsg_iov_cb, dma_buf,
				iov_addr);
		if(!iov_ept) {
			dev_err(&rpdev->dev, "iov_ept create failed\n");
			__dma_buf_free(rpdev, dma_buf);
		}
	}
}

static void rpmsg_create_fixed_ept(struct rpmsg_channel *rpdev)
{
	lb_ept = rpmsg_create_ept(rpdev, rpmsg_loopback_cb, NULL, loop_addr);
	if (!lb_ept)
		dev_err(&rpdev->dev, "ping looback endpoint create failed\n");
#ifdef RPMSG_DMA
	__create_dma_ept(rpdev);
#endif
#ifdef RPMSG_IOV_DMA
	__create_iov_ept(rpdev);
#endif
}

static int rpmsg_client_probe(struct rpmsg_channel *rpdev)
{
	struct mic_device *mdev = dev_get_drvdata(&rpdev->dev);
	struct device *device = NULL;
	dev_t devno;
	int ret = 0;

	 if(!is_bsp)
		 rpdev->dst = bsp_addr;

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

	dev_info(&rpdev->dev, "%s /dev/%s%d (%d:%d) src 0x%x dst 0x%x\n",
			rpdev->id.name, RPMSG_CLIENT_DEV, rcdev->id,
			MAJOR(devno),MINOR(devno), rpdev->src, rpdev->dst);

	INIT_LIST_HEAD(&rcdev->recvqueue);
	init_waitqueue_head(&rcdev->recv_wait);
	spin_lock_init(&rcdev->recv_spinlock);
	rpmsg_create_fixed_ept(rpdev);
	return ret;

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
	INIT_LIST_HEAD(&g_rblk_list);
	spin_lock_init(&g_rblk_spinlock);
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
	struct rpmsg_channel *rpdev = rcdev->rpdev;

	if(lb_ept)
		rpmsg_destroy_ept(lb_ept);
	if(dma_ept) {
		__free_rblks();
		__dma_buf_free(rpdev, dma_ept->priv);
		rpmsg_destroy_ept(dma_ept);
	}
	if(iov_ept) {
		__dma_buf_free(rpdev, iov_ept->priv);
		rpmsg_destroy_ept(iov_ept);
	}
	/*
	 *  FIXME add code to clean-up the outstanding rblks
	 *  rpmsg_dequeue(..)
	 */

	ida_simple_remove(&g_rpmsg_client_ida, rcdev->id);
	cdev_del(&rcdev->cdev);
	device_destroy(g_rpmsg_client_class, MKDEV(MAJOR(g_rpmsg_client_devno),
				rcdev->id));
	class_destroy(g_rpmsg_client_class);
	unregister_chrdev_region(g_rpmsg_client_devno,
						RPMSG_CLIENT_MAX_NUM_DEVS);
	kfree(rcdev);
	unregister_rpmsg_driver(&rpmsg_client);
}
module_exit(rpmsg_client_fini);

MODULE_DESCRIPTION("Remote processor messaging client driver");
MODULE_LICENSE("GPL v2");
