/*
 * Remote Processor Framework
 *
 * Copyright(c) 2011 Texas Instruments, Inc.
 * Copyright(c) 2011 Google, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name Texas Instruments nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MIC_PROC_H
#define MIC_PROC_H

#include <linux/types.h>
#include <linux/klist.h>
#include <linux/mutex.h>
#include <linux/virtio.h>
#include <linux/vringh.h>
#include <linux/completion.h>
#include <linux/idr.h>

struct resource_table {
	u32 ver;
	u32 num;
	u32 h2c_db;
	u32 c2h_db;
	u32 offset[0];
} __packed;

struct fw_rsc_hdr {
	u32 type;
	u8 data[0];
} __packed;

enum fw_resource_type {
	RSC_CARVEOUT	= 0,
	RSC_DEVMEM	= 1,
	RSC_TRACE	= 2,
	RSC_VDEV	= 3,
	RSC_LAST	= 4,
};

#define FW_RSC_ADDR_ANY (0xFFFFFFFFFFFFFFFF)

struct fw_rsc_vdev_vring {
	unsigned long da;
	u32 align;
	u32 num;
	u32 notifyid;
	u32 reserved;
} __packed;

struct fw_rsc_vdev {
	u32 id;
	u32 notifyid;
	u32 dfeatures;
	u32 gfeatures;
	u32 config_len;
	u8 status;
	u8 num_of_vrings;
	u8 reserved[2];
	struct fw_rsc_vdev_vring vring[0];
} __packed;

struct fw_rsc_vdev_buf_desc{
	unsigned long addr;
	u32 len;
} __packed;

struct fw_rsc_vdev_config {
	struct fw_rsc_vdev_buf_desc rproc_desc;
	struct fw_rsc_vdev_buf_desc lproc_desc;
} __packed;

#define RSC_VDEV_CONFIG_SIZE	(sizeof(struct fw_rsc_vdev_config))

/* we currently support only two vrings per rvdev */

#define RVDEV_NUM_VRINGS 4

/**
 * struct rproc_vringh - remoteproc host vring
 * @vrh: Host side virtio ring
 * @rvring: Virtio ring associated with the device
 * @vringh_cb: Callback notifying virtio driver about new buffers
 */
struct rproc_vring;
struct rproc_vringh {
	struct vringh vrh;
	struct rproc_vring *rvring;
	vrh_callback_t *vringh_cb;
};

/**
 * struct rproc_vring - remoteproc vring state
 * @va:	virtual address
 * @dma: dma address
 * @len: length, in bytes
 * @da: device address
 * @align: vring alignment
 * @notifyid: rproc-specific unique vring index
 * @rvdev: remote vdev
 * @vq: the virtqueue of this vring
 * @rvringh: the reversed host-side vring
 */
struct rproc_vring {
	void *va;
	dma_addr_t dma;
	int len;
	unsigned long da;
	u32 align;
	int notifyid;
	struct rproc_vdev *rvdev;
	struct virtqueue *vq;
	struct rproc_vringh *rvringh;
};

/**
 * struct rproc_vdev - remoteproc state for a supported virtio device
 * @node: list node
 * @rproc: the rproc handle
 * @vdev: the virio device
 * @vring: the vrings for this vdev
 * @rsc_offset: offset of the vdev's resource entry
 */
struct rproc_vdev {
	struct list_head node;
	void *rproc;
	struct virtio_device vdev;
	struct rproc_vring vring[RVDEV_NUM_VRINGS];
	u32 rsc_offset;
};

struct mic_proc_resourcetable {
	struct resource_table		main_hdr;
	u32				offset[1];
	struct fw_rsc_hdr		rsc_hdr_vdev;
	struct fw_rsc_vdev		rsc_vdev;
	struct fw_rsc_vdev_vring	rsc_ring0;
	struct fw_rsc_vdev_vring	rsc_ring1;
	struct fw_rsc_vdev_vring	rsc_ring2;
	struct fw_rsc_vdev_vring	rsc_ring3;
	struct fw_rsc_vdev_config	rsc_vdev_cfg;
};

struct mic_proc {
	int max_notifyid;
	struct mic_device *mdev;
	struct device *dev;
	struct list_head lvdevs;
#ifndef INTEL_MIC_CARD
	struct resource_table *table_ptr;
#else
	struct resource_table __iomem *table_ptr;
#endif
	dma_addr_t table_dma_addr;
	struct idr notifyids;
	void *priv;
	int db;
	struct mic_irq *db_cookie;
};

static inline struct rproc_vdev *vdev_to_rvdev(struct virtio_device *vdev)
{
	return container_of(vdev, struct rproc_vdev, vdev);
}

static inline struct rproc *vdev_to_rproc(struct virtio_device *vdev)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);

	return rvdev->rproc;
}

static inline struct rproc_vring *vringh_to_rvring(struct vringh *vrh)
{
	struct rproc_vringh *rvrh = container_of(vrh, struct rproc_vringh, vrh);
	return rvrh->rvring;
}

#ifndef INTEL_MIC_CARD
int mic_proc_init(struct mic_device *mdev);
void mic_proc_uninit(struct mic_device *mdev);
#else
int mic_proc_init(struct mic_driver *mdrv);
#endif

#endif /* MIC_PROC_H */
