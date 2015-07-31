#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include <linux/vringh.h>
#include <linux/idr.h>
#include <asm/cacheflush.h>
#include <linux/scatterlist.h>
#include <linux/mic_common.h>
#include "mic_device.h"
#include "mic_smpt.h"
#include "mic_intr.h"
#include "../common/mic_proc.h"

struct mic_proc_resourcetable mproc_resourcetable
	__attribute__((section(".resource_table"), aligned(PAGE_SIZE))) =
{
	.main_hdr = {
		.ver =		1,			/* version */
		.num =		1,			/* 1 entry for rpmsg */
		.h2c_db =	0,
		.c2h_db =	0,
	},
	.offset = {					/* offsets to our resource entries */
		offsetof(struct mic_proc_resourcetable, rsc_hdr_vdev),
	},
	.rsc_hdr_vdev = {
		.type =		RSC_VDEV,		/* vdev resource */
	},
	.rsc_vdev = {
		.id =		VIRTIO_ID_RPMSG,	/* found in virtio_ids.h */
		.notifyid =	0,			/* magic number for IPC */
		.dfeatures =	1,			/* features - VIRTIO_RPMSG_F_NS*/
		.gfeatures =	0,			/* negotiated features - blank */
		.config_len =	RSC_VDEV_CONFIG_SIZE,	/* config len */
		.status =	0,			/* status - updated by bsp */
		.num_of_vrings=	2,			/* we have 2 rings */
		.reserved =	{ 0, 0},		/* reserved */
	},
	.rsc_ring0 = {
		.da =		0,			/* we don't (??) care about the da */
		.align =	PAGE_SIZE,		/* alignment */
		.num =		128,			/* number of buffers */
		.notifyid =	0,			/* magic number for IPC */
		.reserved =	0,			/* reserved - 0 */
	},
	.rsc_ring1 = {
		.da =		0,			/* we don't (??) care about the da */
		.align =	PAGE_SIZE,		/* alignment */
		.num =		128,			/* number of buffers */
		.notifyid =	0,			/* magic number for IPC */
		.reserved =	0,			/* reserved - 0 */
	},
	.rsc_ring2 = {
		.da =		0,			/* we don't (??) care about the da */
		.align =	PAGE_SIZE,		/* alignment */
		.num =		128,			/* number of buffers */
		.notifyid =	0,			/* magic number for IPC */
		.reserved =	0,			/* reserved - 0 */
	}
};

struct mic_proc_resourcetable *lrsc = &mproc_resourcetable;

static int vrh_id_map[RVDEV_NUM_VRINGS] = { 0, -1, -1 };
static int vrg_id_map[RVDEV_NUM_VRINGS] = { 1,  2, -1 };

static bool mic_proc_virtio_notify(struct virtqueue *vq)
{
	struct rproc_vring *lvring = vq->priv;
	struct mic_proc *mic_proc;
	s8 db;

	mic_proc = (struct mic_proc *)lvring->rvdev->rproc;
	db = mic_proc->table_ptr->h2c_db;

	mic_proc->mdev->ops->send_intr(mic_proc->mdev, db);

	return true;
}

static void mic_proc_virtio_vringh_notify(struct vringh *vrh)
{
	struct rproc_vring *lvring = vringh_to_rvring(vrh);
	struct mic_proc *mic_proc;
	s8 db;

	mic_proc = (struct mic_proc *)lvring->rvdev->rproc;
	db = mic_proc->table_ptr->h2c_db;

	mic_proc->mdev->ops->send_intr(mic_proc->mdev, db);
}


static void mic_proc_virtio_del_vqs(struct virtio_device *vdev)
{
	printk(KERN_INFO "%s: Not implemented\n", __func__);
}

static u8 mic_proc_virtio_get_status(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;

	return rsc->status;
}

static void mic_proc_virtio_set_status(struct virtio_device *vdev, u8 status)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;

	rsc->status = status;
	dev_dbg(&vdev->dev, "status: %d\n", status);

}

static void mic_proc_virtio_reset(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;

	rsc->status = 0;
	dev_dbg(&vdev->dev, "reset !\n");

}

/* provide the vdev features as retrieved from the firmware */
static u64 mic_proc_virtio_get_features(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;

	dev_dbg(&vdev->dev,"%s: gfeatures %x\n", __func__,rsc->gfeatures);
	return rsc->gfeatures;
}

static int mic_proc_virtio_finalize_features(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;

	vring_transport_features(vdev);

	dev_dbg(&vdev->dev,"%s:gfeatures %x dfeatures %x vdev->features %llx\n",
			__func__,rsc->gfeatures,rsc->dfeatures,vdev->features);
	return 0;
}

/* Helper function that creates and initializes the host virtio ring */
static struct vringh *mic_proc_create_new_vringh(struct rproc_vring *lvring,
					unsigned int index,
					vrh_callback_t callback)
{
	struct rproc_vringh *lvrh = NULL;
	struct rproc_vdev *lvdev = lvring->rvdev;
	struct virtio_device *vdev = &lvdev->vdev;
	int err;

	lvrh = kzalloc(sizeof(*lvrh), GFP_KERNEL);
	err = -ENOMEM;
	if (!lvrh)
		goto err;

	/* initialize the host virtio ring */
	lvrh->vringh_cb = callback;
	lvrh->vrh.notify = mic_proc_virtio_vringh_notify;

	vring_init(&lvrh->vrh.vring, lvring->len, lvring->va, lvring->align);

	/*
	 * Create the new vring host, and tell we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	err = vringh_init_kern(&lvrh->vrh,
				mic_proc_virtio_get_features(&lvdev->vdev),
				lvring->len,
				false,
				lvrh->vrh.vring.desc,
				lvrh->vrh.vring.avail,
				lvrh->vrh.vring.used);
	if (err) {
		dev_err(&vdev->dev, "vringh_init_kern failed\n");
		goto err;
	}

	lvring->rvringh = lvrh;
	lvrh->rvring = lvring;
	return &lvrh->vrh;
err:
	kfree(lvrh);
	return ERR_PTR(err);
}

static void mic_proc_virtio_get(struct virtio_device *vdev, unsigned offset,
							void *buf, unsigned len)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;
	void *cfg;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;
	cfg = &rsc->vring[rsc->num_of_vrings];

	if (offset + len > rsc->config_len || offset + len < len) {
		dev_err(&vdev->dev, "mic_proc_virtio_get: access out of bounds\n");
		return;
	}
	dev_info(&vdev->dev, "%s: offset %d table_ptr %p rsc %p, cfg %p\n",
			__func__, offset, mic_proc->table_ptr, rsc, cfg);
	memcpy(buf, cfg + offset, len);
}

static void mic_proc_virtio_set(struct virtio_device *vdev, unsigned offset,
		      const void *buf, unsigned len)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct fw_rsc_vdev *rsc;
	void *cfg;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;
	cfg = &rsc->vring[rsc->num_of_vrings];

	if (offset + len > rsc->config_len || offset + len < len) {
		dev_err(&vdev->dev, "rproc_virtio_set: access out of bounds\n");
		return;
	}
	dev_info(&vdev->dev, "%s: offset %d table_ptr %p rsc %p, cfg %p\n",
			__func__, offset, mic_proc->table_ptr, rsc, cfg);
	memcpy(cfg + offset, buf, len);
}

int mic_proc_alloc_vring(struct rproc_vdev *lvdev, int i)
{
	struct mic_proc *mic_proc = lvdev->rproc;
	struct device *dev = mic_proc->dev;
	struct rproc_vring *lvring = &lvdev->vring[i];
	struct fw_rsc_vdev *rsc;
	dma_addr_t dma;
	void *va;
	int ret, size, notifyid;

	/* actual size of vring (in bytes) */
	size = PAGE_ALIGN(vring_size(lvring->len, lvring->align));

	/*
	 * Allocate non-cacheable memory for the vring. In the future
	 * this call will also configure the IOMMU for us
	 */
	va = dma_alloc_coherent(dev->parent, size, &dma, GFP_KERNEL);
	if (!va) {
		dev_err(dev->parent, "dma_alloc_coherent failed\n");
		return -EINVAL;
	}

	/*
	 * Assign an rproc-wide unique index for this vring
	 * TODO: assign a notifyid for rvdev updates as well
	 * TODO: support predefined notifyids (via resource table)
	 */
	ret = idr_alloc(&mic_proc->notifyids, lvring, 0, 0, GFP_KERNEL);
	if (ret < 0) {
		dev_err(dev, "idr_alloc failed: %d\n", ret);
		dma_free_coherent(dev->parent, size, va, dma);
		return ret;
	}
	notifyid = ret;

	dev_info(dev, "vring%d: va %p dma %llx size %x idr %d\n", i, va,
				(unsigned long long)dma, size, notifyid);

	lvring->va = va;
	lvring->dma = dma;
	lvring->notifyid = notifyid;

	/*
	 * Let the rproc know the notifyid and da of this vring.
	 * Not all platforms use dma_alloc_coherent to automatically
	 * set up the iommu. In this case the device address (da) will
	 * hold the physical address and not the device address.
	 */
	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;
	rsc->vring[i].da = dma;
	rsc->vring[i].notifyid = notifyid;
	return 0;
}


int mic_proc_map_vring(struct rproc_vdev *lvdev, int i)
{
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct device *dev = mic_proc->dev;
	struct rproc_vring *lvring = &lvdev->vring[i];
	struct fw_rsc_vdev *rsc;
	dma_addr_t dma;
	void *va;
	int size, notifyid;

	rsc = (void *)mic_proc->table_ptr + lvdev->rsc_offset;
	dma = rsc->vring[i].da;
	notifyid = rsc->vring[i].notifyid;

	/* actual size of vring (in bytes) */
	size = PAGE_ALIGN(vring_size(lvring->len, lvring->align));

	va = ioremap_cache(dma, size);
	if (!va) {
		dev_err(dev, "ioremap failed\n");
		return -EINVAL;
	}

	dev_info(dev, "vring%d: va %p dma %llx size %d idr %d\n", i, va,
				(unsigned long long)dma, size, notifyid);

	lvring->va = va;
	lvring->dma = dma;
	lvring->notifyid = notifyid;
	return 0;
}

static struct virtqueue *lp_find_vq(struct virtio_device *vdev,
				    unsigned id,
				    void (*callback)(struct virtqueue *vq),
				    const char *name)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct device *dev = mic_proc->dev;
	struct rproc_vring *lvring;
	struct virtqueue *vq;
	void *addr;
	int len, ret, i;

	if (id >= ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-EINVAL);

	i = vrg_id_map[id];

	BUG_ON(i == -1);

	lvring = &lvdev->vring[i];

	BUG_ON(lvring->vq != NULL);
	BUG_ON(lvring->rvringh != NULL);


	if (i == ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-EINVAL);

	ret = mic_proc_alloc_vring(lvdev, i);
	if (ret)
		return ERR_PTR(ret);

	lvring = &lvdev->vring[i];
	addr = lvring->va;
	len = lvring->len;

	dev_info(dev, "vring%d: va %p qsz %d notifyid %d\n",
					i, addr, len, lvring->notifyid);

	/*
	 * Create the new vq, and tell virtio we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	vq = vring_new_virtqueue(i, len, lvring->align, vdev, false, addr,
					mic_proc_virtio_notify, callback, name);
	if (!vq) {
		dev_err(dev, "vring_new_virtqueue %s failed\n", name);
#if 0
		/*
		 *TODO: Implement the cleanup features.
		 */
		mic_proc_free_vring(lvring);
#endif
		return ERR_PTR(-ENOMEM);
	}

	lvring->vq = vq;
	vq->priv = lvring;

	return vq;
}

/*
 * TODO: Fix the following two routines to interrupt only the virtqueue which
 * has some work to do.
 */
static irqreturn_t mic_proc_vq_interrupt(struct mic_proc *mic_proc, int notifyid)
{
	struct rproc_vdev *lvdev;
	struct rproc_vring *lvring;
	int ret = IRQ_NONE;

	if(mic_proc && mic_proc->priv) {
		lvdev = mic_proc->priv;
		lvring = &lvdev->vring[notifyid];
		switch (notifyid) {
			case 0:
				ret = vring_interrupt(1, lvring->vq);
				break;
			case 1:
				if (lvring->rvringh && lvring->rvringh->vringh_cb){
					lvring->rvringh->vringh_cb(&lvring->rvdev->vdev,
							&lvring->rvringh->vrh); 
					ret = IRQ_HANDLED;
				} else {
					printk(KERN_INFO "%s: Failed interrupt!"
						"notifyid %d", __func__,
								notifyid);
					ret = IRQ_NONE;
				}
				break;
			default:
				printk(KERN_INFO "%s: Failed interrupt!"
						"notifyid %d ", __func__,
								notifyid);
				ret = IRQ_NONE;
		}
	} else
		printk(KERN_INFO "%s: Failed interrupt! mic_proc %p priv %p\n",
					       __func__, mic_proc, mic_proc->priv);
	return ret;
}

static irqreturn_t mic_proc_callback(int irq, void *data)
{
	struct mic_proc *mic_proc = data;
	int i;

	printk(KERN_INFO "%s mic_proc %p\n",__func__, mic_proc);
	if (unlikely(!mic_proc)) {
		printk(KERN_DEBUG "In %s %p\n",__func__, mic_proc);
		return IRQ_HANDLED;
	}

	for (i=0; i <= mic_proc->max_notifyid; i++) {
		if(mic_proc_vq_interrupt(mic_proc,i) == IRQ_NONE) {
			printk(KERN_DEBUG "%s No work to do vq %d\n",__func__,i);
		}
	}
	return IRQ_HANDLED;
}

static int mic_proc_virtio_find_vqs(struct virtio_device *vdev, unsigned nvqs,
		       struct virtqueue *vqs[],
		       vq_callback_t *callbacks[],
		       const char *names[])
{
	int i, ret=0;

	for (i = 0; i < nvqs; i++) {
		vqs[i] = lp_find_vq(vdev, i, callbacks[i], names[i]);
		if (IS_ERR(vqs[i])) {
			ret = PTR_ERR(vqs[i]);
			dev_dbg(&vdev->dev,"mic_proc: failed find rp_find_vq\n");
		}
	}
	return ret;
}

static struct virtio_config_ops mic_proc_virtio_config_ops = {
	.get_features	= mic_proc_virtio_get_features,
	.finalize_features = mic_proc_virtio_finalize_features,
	.find_vqs	= mic_proc_virtio_find_vqs,
	.del_vqs	= mic_proc_virtio_del_vqs,
	.reset		= mic_proc_virtio_reset,
	.set_status	= mic_proc_virtio_set_status,
	.get_status	= mic_proc_virtio_get_status,
	.get		= mic_proc_virtio_get,
	.set		= mic_proc_virtio_set,
};

static void mic_proc_vdev_release(struct device *dev)
{
	printk(KERN_INFO "%s: Not implemented yet\n", __func__);
}

void mic_proc_remove_virtio_dev(struct rproc_vdev *lvdev)
{
	unregister_virtio_device(&lvdev->vdev);
}

static struct vringh *lp_find_vrh(struct virtio_device *vdev,
				unsigned id,
				vrh_callback_t callback)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	struct mic_proc *mic_proc = (struct mic_proc *)lvdev->rproc;
	struct device *dev = mic_proc->dev;
	struct rproc_vring *lvring;
	struct vringh *vrh;
	void *addr;
	int len, ret, i;

	if (id >= ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-EINVAL);


	/* Find available slot for a new host vring */
	i = vrh_id_map[id];

	BUG_ON(i == -1);

	lvring = &lvdev->vring[i];
	BUG_ON(lvring->vq != NULL);
	BUG_ON(lvring->rvringh != NULL);

	if (i == ARRAY_SIZE(lvdev->vring))
		return ERR_PTR(-ENODEV);

	ret = mic_proc_alloc_vring(lvdev, i);
	if (ret)
		return ERR_PTR(ret);

	addr = lvring->va;
	len = lvring->len;

	dev_info(dev, "vringh%d: va %p qsz %d notifyid %d\n",
					i, addr, len, lvring->notifyid);

	/*
	 * Create the new vringh, and tell virtio we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	vrh = mic_proc_create_new_vringh(lvring, i, callback);
	if (!vrh) {
		//mic_proc_free_vring(lvring);
		return ERR_PTR(-ENOMEM);
	}

	return vrh;
}

static void __mic_proc_virtio_del_vrhs(struct virtio_device *vdev)
{
	struct rproc_vdev *lvdev = vdev_to_rvdev(vdev);
	int i, num_of_vrings = ARRAY_SIZE(lvdev->vring);

	for (i = 0; i < num_of_vrings; i++) {
		struct rproc_vring *lvring = &lvdev->vring[i];
		if (!lvring->rvringh)
			continue;
		kfree(lvring->rvringh);
		lvring->rvringh = NULL;
		//mic_proc_free_vring(lvring);
	}
}

static void mic_proc_virtio_del_vrhs(struct virtio_device *vdev)
{
	printk(KERN_INFO "%s: Not implemented completely\n", __func__);
	__mic_proc_virtio_del_vrhs(vdev);
}

static int mic_proc_virtio_find_vrhs(struct virtio_device *vdev, unsigned nhvrs,
			 struct vringh *vrhs[],
			 vrh_callback_t *callbacks[])
{
	int i, ret;

	for (i = 0; i < nhvrs; ++i) {
		vrhs[i] = lp_find_vrh(vdev, i, callbacks[i]);
		if (IS_ERR(vrhs[i])) {
			ret = PTR_ERR(vrhs[i]);
			goto error;
		}
	}
	return 0;
error:
	__mic_proc_virtio_del_vrhs(vdev);
	return ret;
}

static struct vringh_config_ops mic_proc_virtio_vringh_ops = {
	.find_vrhs	= mic_proc_virtio_find_vrhs,
	.del_vrhs	= mic_proc_virtio_del_vrhs,
};


int mic_proc_add_virtio_dev(struct mic_proc *mic_proc, struct rproc_vdev *lvdev, int id)
{
	struct device *dev = mic_proc->dev;
	struct virtio_device *vdev = &lvdev->vdev;
	int ret;

	vdev->id.device	= id;
	vdev->config = &mic_proc_virtio_config_ops;
	vdev->vringh_config = &mic_proc_virtio_vringh_ops;
	vdev->dev.parent = dev;
	vdev->dev.release = mic_proc_vdev_release;

	ret = register_virtio_device(vdev);
	if (ret) {
		dev_err(dev, "mic_proc: failed to register vdev: %d\n", ret);
		goto out;
	}

	dev_info(dev, "registered %s (type %d)\n", dev_name(&vdev->dev), id);
out:
	return ret;
}


static int
mic_proc_parse_vring(struct rproc_vdev *lvdev, struct fw_rsc_vdev *rsc, int i)
{
	struct fw_rsc_vdev_vring *vring = &rsc->vring[i];
	struct rproc_vring *lvring = &lvdev->vring[i];

	printk(KERN_INFO "mic_proc: vdev rsc: vring%d: da %lx, qsz %d, align %d\n",
				i, vring->da, vring->num, vring->align);

	/* make sure reserved bytes are zeroes */
	if (vring->reserved) {
		printk(KERN_INFO "mic_proc: vring rsc has non zero reserved bytes\n");
		return -EINVAL;
	}

	/* verify queue size and vring alignment are sane */
	if (!vring->num || !vring->align) {
		printk(KERN_INFO "mic_proc: invalid qsz (%d) or alignment (%d)\n",
						vring->num, vring->align);
		return -EINVAL;
	}

	lvring->len = vring->num;
	lvring->align = vring->align;
	lvring->rvdev = lvdev;

	return 0;
}
static int mic_proc_handle_vdev(struct mic_proc *mic_proc, struct fw_rsc_vdev *rsc,
							int offset, int avail)
{
	struct rproc_vdev *lvdev;
	int i, ret;

	/* make sure resource isn't truncated */
	if (sizeof(*rsc)+ rsc->num_of_vrings * sizeof(struct fw_rsc_vdev_vring)
			+ rsc->config_len > avail) {
		printk(KERN_INFO "mic_proc: vdev rsc is truncated\n");
		return -EINVAL;
	}

	printk(KERN_INFO "mic_proc: vdev rsc: id %d gfeatures %x dfeatures %x"
			"cfg len %d %dvrings\n",rsc->id, rsc->gfeatures,
			rsc->dfeatures, rsc->config_len, rsc->num_of_vrings);

	/* we currently support only two vrings per lvdev */
	if (rsc->num_of_vrings > ARRAY_SIZE(lvdev->vring)) {
		printk(KERN_INFO "mic_proc: too many vrings: %d\n",
				rsc->num_of_vrings);
		return -EINVAL;
	}

	lvdev = kzalloc(sizeof(struct rproc_vdev), GFP_KERNEL);
	if (!lvdev)
		return -ENOMEM;

	/* parse the vrings */
	for (i = 0; i < rsc->num_of_vrings; i++) {
		ret = mic_proc_parse_vring(lvdev, rsc, i);
		if (ret)
			goto free_lvdev;
	}

	/* remember the resource offset*/
	lvdev->rsc_offset = offset;
	lvdev->rproc = (void*)mic_proc; // FIXME: Remove the Hack

	list_add_tail(&lvdev->node, &mic_proc->lvdevs);
	mic_proc->priv = lvdev;

	/* it is now safe to add the virtio device */
	ret = mic_proc_add_virtio_dev(mic_proc, lvdev, rsc->id);
	if (ret)
		goto remove_lvdev;
	return 0;
remove_lvdev:
	list_del(&lvdev->node);
free_lvdev: kfree(lvdev);
	return ret;
}

static int mic_proc_count_vrings(struct mic_proc *mic_proc, struct fw_rsc_vdev *rsc,
			      int offset, int avail)
{
	/* Summarize the number of notification IDs */
	mic_proc->max_notifyid += rsc->num_of_vrings;

	return 0;
}

typedef int (*mic_proc_handle_resource_t)(struct mic_proc *mic_proc,
				 void *, int offset, int avail);

static mic_proc_handle_resource_t mic_proc_vdev_handler[RSC_LAST] = {
	[RSC_VDEV] = (mic_proc_handle_resource_t)mic_proc_handle_vdev,
};

static mic_proc_handle_resource_t mic_proc_count_vrings_handler[RSC_LAST] = {
	[RSC_VDEV] = (mic_proc_handle_resource_t)mic_proc_count_vrings,
};

/* handle firmware resource entries before booting the remote processor */
static int mic_proc_handle_resources(struct mic_proc *mic_proc, int len,
				  mic_proc_handle_resource_t handlers[RSC_LAST])
{
	mic_proc_handle_resource_t handler;
	struct device *dev = mic_proc->dev;
	int ret = 0, i;

	for (i = 0; i < mic_proc->table_ptr->num; i++) {
		int offset = mic_proc->table_ptr->offset[i];
		struct fw_rsc_hdr *hdr = (void *)mic_proc->table_ptr + offset;
		int avail = len - offset - sizeof(*hdr);
		void *rsc = (void *)hdr + sizeof(*hdr);

		/* make sure table isn't truncated */
		if (avail < 0) {
			dev_err(dev, "mic_proc: rsc table is truncated\n");
			return -EINVAL;
		}
		if (hdr->type >= RSC_LAST) {
			dev_err(dev, "mic_proc: unsupported resource %d\n",
					hdr->type);
			continue;
		}
		handler = handlers[hdr->type];
		if (!handler)
			continue;

		ret = handler(mic_proc, rsc, offset + sizeof(*hdr), avail);
		if (ret)
			break;
	}
	return ret;
}

/*
 * Take the mic_proc and attach the rings to virtio devices to register
 * on the host processor.
 *
 */
static int mic_proc_config_virtio(struct mic_proc *mic_proc)
{
	int ret, tablesz = sizeof(struct mic_proc_resourcetable);
	struct mic_device *mdev = mic_proc->mdev;
	struct mic_proc_resourcetable *rsc_va;
	struct device *dev = mic_proc->dev;
	char irqname[10];

	/* allocate resource table, copy lrsc, map va*/
	rsc_va = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if(!rsc_va) {
		dev_err(dev, "%s %d err %d\n",
				__func__, __LINE__, -ENOMEM);
		ret = -ENOMEM;
		return ret;
	}

	memcpy(rsc_va, lrsc, tablesz);
	mic_proc->table_ptr = (struct resource_table *)rsc_va;

	snprintf(irqname, sizeof(irqname), "mic-virtio%d", rsc_va->rsc_vdev.id);
	mic_proc->db = mic_next_db(mdev);
	mic_proc->db_cookie = mic_request_threaded_irq(mdev,
					       mic_proc_callback,
					       NULL, irqname, mic_proc,
					       mic_proc->db, MIC_INTR_DB);
	if (IS_ERR(mic_proc->db_cookie)) {
		ret = PTR_ERR(mic_proc->db_cookie);
		dev_err(dev, "request irq failed\n");
		goto free_rsc_table;
	}
	rsc_va->main_hdr.c2h_db = mic_proc->db;

	mic_proc->table_dma_addr = mic_map_single(mdev, rsc_va, PAGE_SIZE);
	if(mic_map_error(mic_proc->table_dma_addr)){
		dev_err(dev, "%s %d err %d\n",  __func__, __LINE__, -ENOMEM);
		goto free_irq;
	}

	mdev->ops->write_spad(mdev, MIC_RPLO_SPAD, mic_proc->table_dma_addr);
	mdev->ops->write_spad(mdev, MIC_RPHI_SPAD, mic_proc->table_dma_addr >> 32);

	dev_info(dev, "rsc_dma_addr %llx, db %d, db_cookie %p",
			mic_proc->table_dma_addr, mic_proc->db,
			mic_proc->db_cookie);

	/* count the number of notify-ids */
	mic_proc->max_notifyid = -1;
	ret = mic_proc_handle_resources(mic_proc, tablesz, mic_proc_count_vrings_handler);
	if (ret) {
		dev_err(dev, "rsc table resource count failed\n");
		goto unmap_dma_addr;
	}

	/* look for virtio devices and register them */
	ret = mic_proc_handle_resources(mic_proc, tablesz, mic_proc_vdev_handler);
	if (ret) {
		dev_err(dev, "rsc table handle vdev failed\n");
		goto unmap_dma_addr;
	}
	return 0;

unmap_dma_addr:
	mic_unmap_single(mdev, mic_proc->table_dma_addr, PAGE_SIZE);
free_irq:
	mic_free_irq(mdev, mic_proc->db_cookie, mic_proc);
free_rsc_table:
	kfree(rsc_va);
	mic_proc->table_ptr = NULL;
	return ret;
}

int mic_proc_init(struct mic_device *mdev)
{
	struct mic_proc *mic_proc;
	int ret = -ENOMEM;

	mic_proc = kzalloc(sizeof(struct mic_proc), GFP_KERNEL);
	if (!mic_proc) {
		dev_err(mdev->sdev->parent,"%s: kzalloc failed\n", __func__);
		return ret;
	}

	INIT_LIST_HEAD(&mic_proc->lvdevs);

	mic_proc->dev = mdev->sdev->parent;
	mic_proc->mdev = mdev;
	mdev->mic_proc = mic_proc;
	ret = mic_proc_config_virtio(mic_proc);
	if(ret) {
		dev_err(mdev->sdev->parent,"%s: virtio config failed\n", __func__);
		goto err;
	}
	return 0;
err:
	kfree(mic_proc);
	return ret;
}

void mic_proc_uninit(struct mic_device *mdev)
{
	struct mic_proc *mic_proc;

	mic_proc = mdev->mic_proc;
	mic_unmap_single(mdev, mic_proc->table_dma_addr, PAGE_SIZE);
	mic_free_irq(mdev, mic_proc->db_cookie, mic_proc);
	kfree(mic_proc->table_ptr);
	kfree(mic_proc);
}
