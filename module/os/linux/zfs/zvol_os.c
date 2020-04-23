/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2012, 2020 by Delphix. All rights reserved.
 */

#include <sys/dataset_kstats.h>
#include <sys/dbuf.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_dir.h>
#include <sys/zap.h>
#include <sys/zfeature.h>
#include <sys/zil_impl.h>
#include <sys/dmu_tx.h>
#include <sys/zio.h>
#include <sys/zfs_rlock.h>
#include <sys/spa_impl.h>
#include <sys/zvol.h>
#include <sys/zvol_impl.h>
#include <sys/vdev_impl.h>

#include <linux/blkdev_compat.h>
#include <linux/task_io_accounting_ops.h>

#define	ZVOL_DUMPSIZE		"dumpsize"

extern int zfs_set_prop_nvlist(const char *, zprop_source_t,
    nvlist_t *, nvlist_t *);

unsigned int zvol_major = ZVOL_MAJOR;
unsigned int zvol_request_sync = 0;
unsigned int zvol_prefetch_bytes = (128 * 1024);
unsigned long zvol_max_discard_blocks = 16384;
unsigned int zvol_threads = 32;

/*
 * This flag is specific to the Delphix product.  It always exports a phys
 * block size of 512 bytes regardless of the volblocksize.
 */
int zvol_fake_phys_block_size = 1;

struct zvol_state_os {
	struct gendisk		*zvo_disk;	/* generic disk */
	struct request_queue	*zvo_queue;	/* request queue */
	dataset_kstats_t	zvo_kstat;	/* zvol kstats */
	dev_t			zvo_dev;	/* device id */
};

taskq_t *zvol_taskq;
static struct ida zvol_ida;

typedef struct zv_request {
	zvol_state_t	*zv;
	struct bio	*bio;
	taskq_ent_t	ent;
} zv_request_t;

typedef struct zvol_extent {
	list_node_t	ze_node;
	dva_t		ze_dva;		/* dva associated with this extent */
	uint64_t	ze_nblks;	/* number of blocks in extent */
} zvol_extent_t;

/*
 * Given a path, return TRUE if path is a ZVOL.
 */
static boolean_t
zvol_is_zvol_impl(const char *device)
{
	struct block_device *bdev;
	unsigned int major;

	bdev = vdev_lookup_bdev(device);
	if (IS_ERR(bdev))
		return (B_FALSE);

	major = MAJOR(bdev->bd_dev);
	bdput(bdev);

	if (major == zvol_major)
		return (B_TRUE);

	return (B_FALSE);
}

static void
uio_from_bio(uio_t *uio, struct bio *bio)
{
	uio->uio_bvec = &bio->bi_io_vec[BIO_BI_IDX(bio)];
	uio->uio_iovcnt = bio->bi_vcnt - BIO_BI_IDX(bio);
	uio->uio_loffset = BIO_BI_SECTOR(bio) << 9;
	uio->uio_segflg = UIO_BVEC;
	uio->uio_limit = MAXOFFSET_T;
	uio->uio_resid = BIO_BI_SIZE(bio);
	uio->uio_skip = BIO_BI_SKIP(bio);
}

static void
zvol_write_dumpio(zvol_state_t *zv, struct bio *bio, uio_t *uio)
{
	int error = 0;
	zvol_extent_t *ze;
	vdev_t *vd;
	offset_t offset = uio->uio_loffset;
	ssize_t size = uio.uio_resid;

	if (size == 0)
		goto done;

	is (offset + size > zv->zv_volsize) {
		error = SET_ERROR(EINVAL);
		goto done;
	}

	spa_t *spa = dmu_objset_spa(zv->zv_objset);

	unsigned long start_jif = jiffies;
	blk_generic_start_io_acct(zv->zv_zso->zvo_queue, WRITE,
	    bio_sectors(bio), &zv->zv_zso->zvo_disk->part0);

	/* Must be sector aligned, and not stradle a block boundary. */
	if (P2PHASE(offset, DEV_BSIZE) || P2PHASE(offset, DEV_BSIZE) ||
	    P2BOUNDARY(offset, size, zv->zv_volblocksize)) {
	    	error = SET_ERROR(EINVAL);
		goto done;
	}
	ASSERT(size <= zv->zv_volblocksize);


	/* Locate the extent this belongs to */
	ze = list_head(&zv->zv_extents);
	while (offset >= ze->ze_nblks * zv->zv_volblocksize) {
		offset -= ze->ze_nblks * zv->zv_volblocksize;
		ze = list_next(&zv->zv_extents, ze);
	}

	if (ze == NULL) {
	    	error = SET_ERROR(EINVAL);
		goto done;
	}

	spa_config_enter(spa, SCL_STATE, FTAG, RW_READER);
	vd = vdev_lookup_top(spa, DVA_GET_VDEV(&ze->ze_dva));
	offset += DVA_GET_OFFSET(&ze->ze_dva);
	error = zvol_dumpio_vdev(vd, addr, offset, DVA_GET_OFFSET(&ze->ze_dva),
	    size, doread, isdump);


	blk_generic_end_io_acct(zv->zv_zso->zvo_queue,
	    WRITE, &zv->zv_zso->zvo_disk->part0, start_jif);

done:
	rw_exit(&zv->zv_suspend_lock);
	BIO_END_IO(bio, -error);
}

static void
zvol_write(void *arg)
{
	int error = 0;

	zv_request_t *zvr = arg;
	struct bio *bio = zvr->bio;
	uio_t uio = { { 0 }, 0 };
	uio_from_bio(&uio, bio);

	zvol_state_t *zv = zvr->zv;
	ASSERT(zv && zv->zv_open_count > 0);
	ASSERT(zv->zv_zilog != NULL);

	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		zvol_write_dumpio(zv, bio, &uio);
		kmem_free(zvr, sizeof (zv_request_t));
		return;
	}

	/* bio marked as FLUSH need to flush before write */
	if (bio_is_flush(bio))
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	/* Some requests are just for flush and nothing else. */
	if (uio.uio_resid == 0) {
		rw_exit(&zv->zv_suspend_lock);
		BIO_END_IO(bio, 0);
		kmem_free(zvr, sizeof (zv_request_t));
		return;
	}

	ssize_t start_resid = uio.uio_resid;
	unsigned long start_jif = jiffies;
	blk_generic_start_io_acct(zv->zv_zso->zvo_queue, WRITE,
	    bio_sectors(bio), &zv->zv_zso->zvo_disk->part0);

	boolean_t sync =
	    bio_is_fua(bio) || zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS;

	zfs_locked_range_t *lr = zfs_rangelock_enter(&zv->zv_rangelock,
	    uio.uio_loffset, uio.uio_resid, RL_WRITER);

	uint64_t volsize = zv->zv_volsize;
	while (uio.uio_resid > 0 && uio.uio_loffset < volsize) {
		uint64_t bytes = MIN(uio.uio_resid, DMU_MAX_ACCESS >> 1);
		uint64_t off = uio.uio_loffset;
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);

		if (bytes > volsize - off)	/* don't write past the end */
			bytes = volsize - off;

		dmu_tx_hold_write_by_dnode(tx, zv->zv_dn, off, bytes);

		/* This will only fail for ENOSPC */
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}
		error = dmu_write_uio_dnode(zv->zv_dn, &uio, bytes, tx);
		if (error == 0) {
			zvol_log_write(zv, tx, off, bytes, sync);
		}
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	zfs_rangelock_exit(lr);

	int64_t nwritten = start_resid - uio.uio_resid;
	dataset_kstats_update_write_kstats(&zv->zv_zso->zvo_kstat, nwritten);
	task_io_account_write(nwritten);

	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	rw_exit(&zv->zv_suspend_lock);
	blk_generic_end_io_acct(zv->zv_zso->zvo_queue,
	    WRITE, &zv->zv_zso->zvo_disk->part0, start_jif);
	BIO_END_IO(bio, -error);
	kmem_free(zvr, sizeof (zv_request_t));
}

static void
zvol_discard(void *arg)
{
	zv_request_t *zvr = arg;
	struct bio *bio = zvr->bio;
	zvol_state_t *zv = zvr->zv;
	uint64_t start = BIO_BI_SECTOR(bio) << 9;
	uint64_t size = BIO_BI_SIZE(bio);
	uint64_t end = start + size;
	boolean_t sync;
	int error = 0;
	dmu_tx_t *tx;
	unsigned long start_jif;

	ASSERT(zv && zv->zv_open_count > 0);
	ASSERT(zv->zv_zilog != NULL);

	start_jif = jiffies;
	blk_generic_start_io_acct(zv->zv_zso->zvo_queue, WRITE,
	    bio_sectors(bio), &zv->zv_zso->zvo_disk->part0);

	sync = bio_is_fua(bio) || zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS;

	if (end > zv->zv_volsize) {
		error = SET_ERROR(EIO);
		goto unlock;
	}

	/*
	 * Align the request to volume block boundaries when a secure erase is
	 * not required.  This will prevent dnode_free_range() from zeroing out
	 * the unaligned parts which is slow (read-modify-write) and useless
	 * since we are not freeing any space by doing so.
	 */
	if (!bio_is_secure_erase(bio)) {
		start = P2ROUNDUP(start, zv->zv_volblocksize);
		end = P2ALIGN(end, zv->zv_volblocksize);
		size = end - start;
	}

	if (start >= end)
		goto unlock;

	zfs_locked_range_t *lr = zfs_rangelock_enter(&zv->zv_rangelock,
	    start, size, RL_WRITER);

	tx = dmu_tx_create(zv->zv_objset);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
	} else {
		zvol_log_truncate(zv, tx, start, size, B_TRUE);
		dmu_tx_commit(tx);
		error = dmu_free_long_range(zv->zv_objset,
		    ZVOL_OBJ, start, size);
	}
	zfs_rangelock_exit(lr);

	if (error == 0 && sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

unlock:
	rw_exit(&zv->zv_suspend_lock);
	blk_generic_end_io_acct(zv->zv_zso->zvo_queue, WRITE,
	    &zv->zv_zso->zvo_disk->part0, start_jif);
	BIO_END_IO(bio, -error);
	kmem_free(zvr, sizeof (zv_request_t));
}

static void
zvol_read(void *arg)
{
	int error = 0;

	zv_request_t *zvr = arg;
	struct bio *bio = zvr->bio;
	uio_t uio = { { 0 }, 0 };
	uio_from_bio(&uio, bio);

	zvol_state_t *zv = zvr->zv;
	ASSERT(zv && zv->zv_open_count > 0);

	ssize_t start_resid = uio.uio_resid;
	unsigned long start_jif = jiffies;
	blk_generic_start_io_acct(zv->zv_zso->zvo_queue, READ, bio_sectors(bio),
	    &zv->zv_zso->zvo_disk->part0);

	zfs_locked_range_t *lr = zfs_rangelock_enter(&zv->zv_rangelock,
	    uio.uio_loffset, uio.uio_resid, RL_READER);

	uint64_t volsize = zv->zv_volsize;
	while (uio.uio_resid > 0 && uio.uio_loffset < volsize) {
		uint64_t bytes = MIN(uio.uio_resid, DMU_MAX_ACCESS >> 1);

		/* don't read past the end */
		if (bytes > volsize - uio.uio_loffset)
			bytes = volsize - uio.uio_loffset;

		error = dmu_read_uio_dnode(zv->zv_dn, &uio, bytes);
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = SET_ERROR(EIO);
			break;
		}
	}
	zfs_rangelock_exit(lr);

	int64_t nread = start_resid - uio.uio_resid;
	dataset_kstats_update_read_kstats(&zv->zv_zso->zvo_kstat, nread);
	task_io_account_read(nread);

	rw_exit(&zv->zv_suspend_lock);
	blk_generic_end_io_acct(zv->zv_zso->zvo_queue, READ,
	    &zv->zv_zso->zvo_disk->part0, start_jif);
	BIO_END_IO(bio, -error);
	kmem_free(zvr, sizeof (zv_request_t));
}

static MAKE_REQUEST_FN_RET
zvol_request(struct request_queue *q, struct bio *bio)
{
	zvol_state_t *zv = q->queuedata;
	fstrans_cookie_t cookie = spl_fstrans_mark();
	uint64_t offset = BIO_BI_SECTOR(bio) << 9;
	uint64_t size = BIO_BI_SIZE(bio);
	int rw = bio_data_dir(bio);
	zv_request_t *zvr;

	if (bio_has_data(bio) && offset + size > zv->zv_volsize) {
		printk(KERN_INFO
		    "%s: bad access: offset=%llu, size=%lu\n",
		    zv->zv_zso->zvo_disk->disk_name,
		    (long long unsigned)offset,
		    (long unsigned)size);

		BIO_END_IO(bio, -SET_ERROR(EIO));
		goto out;
	}

	if (rw == WRITE) {
		if (unlikely(zv->zv_flags & ZVOL_RDONLY)) {
			BIO_END_IO(bio, -SET_ERROR(EROFS));
			goto out;
		}

		/*
		 * Prevents the zvol from being suspended, or the ZIL being
		 * concurrently opened.  Will be released after the i/o
		 * completes.
		 */
		rw_enter(&zv->zv_suspend_lock, RW_READER);

		/*
		 * Open a ZIL if this is the first time we have written to this
		 * zvol. We protect zv->zv_zilog with zv_suspend_lock rather
		 * than zv_state_lock so that we don't need to acquire an
		 * additional lock in this path.
		 */
		if (zv->zv_zilog == NULL) {
			rw_exit(&zv->zv_suspend_lock);
			rw_enter(&zv->zv_suspend_lock, RW_WRITER);
			if (zv->zv_zilog == NULL) {
				zv->zv_zilog = zil_open(zv->zv_objset,
				    zvol_get_data);
				zv->zv_flags |= ZVOL_WRITTEN_TO;
			}
			rw_downgrade(&zv->zv_suspend_lock);
		}

		zvr = kmem_alloc(sizeof (zv_request_t), KM_SLEEP);
		zvr->zv = zv;
		zvr->bio = bio;
		taskq_init_ent(&zvr->ent);

		/*
		 * We don't want this thread to be blocked waiting for i/o to
		 * complete, so we instead wait from a taskq callback. The
		 * i/o may be a ZIL write (via zil_commit()), or a read of an
		 * indirect block, or a read of a data block (if this is a
		 * partial-block write).  We will indicate that the i/o is
		 * complete by calling BIO_END_IO() from the taskq callback.
		 *
		 * This design allows the calling thread to continue and
		 * initiate more concurrent operations by calling
		 * zvol_request() again. There are typically only a small
		 * number of threads available to call zvol_request() (e.g.
		 * one per iSCSI target), so keeping the latency of
		 * zvol_request() low is important for performance.
		 *
		 * The zvol_request_sync module parameter allows this
		 * behavior to be altered, for performance evaluation
		 * purposes.  If the callback blocks, setting
		 * zvol_request_sync=1 will result in much worse performance.
		 *
		 * We can have up to zvol_threads concurrent i/o's being
		 * processed for all zvols on the system.  This is typically
		 * a vast improvement over the zvol_request_sync=1 behavior
		 * of one i/o at a time per zvol.  However, an even better
		 * design would be for zvol_request() to initiate the zio
		 * directly, and then be notified by the zio_done callback,
		 * which would call BIO_END_IO().  Unfortunately, the DMU/ZIL
		 * interfaces lack this functionality (they block waiting for
		 * the i/o to complete).
		 */
		if (bio_is_discard(bio) || bio_is_secure_erase(bio)) {
			if (zvol_request_sync) {
				zvol_discard(zvr);
			} else {
				taskq_dispatch_ent(zvol_taskq,
				    zvol_discard, zvr, 0, &zvr->ent);
			}
		} else {
			if (zvol_request_sync) {
				zvol_write(zvr);
			} else {
				taskq_dispatch_ent(zvol_taskq,
				    zvol_write, zvr, 0, &zvr->ent);
			}
		}
	} else {
		/*
		 * The SCST driver, and possibly others, may issue READ I/Os
		 * with a length of zero bytes.  These empty I/Os contain no
		 * data and require no additional handling.
		 */
		if (size == 0) {
			BIO_END_IO(bio, 0);
			goto out;
		}

		zvr = kmem_alloc(sizeof (zv_request_t), KM_SLEEP);
		zvr->zv = zv;
		zvr->bio = bio;
		taskq_init_ent(&zvr->ent);

		rw_enter(&zv->zv_suspend_lock, RW_READER);

		/* See comment in WRITE case above. */
		if (zvol_request_sync) {
			zvol_read(zvr);
		} else {
			taskq_dispatch_ent(zvol_taskq,
			    zvol_read, zvr, 0, &zvr->ent);
		}
	}

out:
	spl_fstrans_unmark(cookie);
#if defined(HAVE_MAKE_REQUEST_FN_RET_QC)
	return (BLK_QC_T_NONE);
#endif
}

static int
zvol_open(struct block_device *bdev, fmode_t flag)
{
	zvol_state_t *zv;
	int error = 0;
	boolean_t drop_suspend = B_TRUE;

	rw_enter(&zvol_state_lock, RW_READER);
	/*
	 * Obtain a copy of private_data under the zvol_state_lock to make
	 * sure that either the result of zvol free code path setting
	 * bdev->bd_disk->private_data to NULL is observed, or zvol_free()
	 * is not called on this zv because of the positive zv_open_count.
	 */
	zv = bdev->bd_disk->private_data;
	if (zv == NULL) {
		rw_exit(&zvol_state_lock);
		return (SET_ERROR(-ENXIO));
	}

	mutex_enter(&zv->zv_state_lock);
	/*
	 * make sure zvol is not suspended during first open
	 * (hold zv_suspend_lock) and respect proper lock acquisition
	 * ordering - zv_suspend_lock before zv_state_lock
	 */
	if (zv->zv_open_count == 0) {
		if (!rw_tryenter(&zv->zv_suspend_lock, RW_READER)) {
			mutex_exit(&zv->zv_state_lock);
			rw_enter(&zv->zv_suspend_lock, RW_READER);
			mutex_enter(&zv->zv_state_lock);
			/* check to see if zv_suspend_lock is needed */
			if (zv->zv_open_count != 0) {
				rw_exit(&zv->zv_suspend_lock);
				drop_suspend = B_FALSE;
			}
		}
	} else {
		drop_suspend = B_FALSE;
	}
	rw_exit(&zvol_state_lock);

	ASSERT(MUTEX_HELD(&zv->zv_state_lock));
	ASSERT(zv->zv_open_count != 0 || RW_READ_HELD(&zv->zv_suspend_lock));

	if (zv->zv_open_count == 0) {
		error = -zvol_first_open(zv, !(flag & FMODE_WRITE));
		if (error)
			goto out_mutex;
	}

	if ((flag & FMODE_WRITE) && (zv->zv_flags & ZVOL_RDONLY)) {
		error = -EROFS;
		goto out_open_count;
	}

	zv->zv_open_count++;

	mutex_exit(&zv->zv_state_lock);
	if (drop_suspend)
		rw_exit(&zv->zv_suspend_lock);

	check_disk_change(bdev);

	return (0);

out_open_count:
	if (zv->zv_open_count == 0)
		zvol_last_close(zv);

out_mutex:
	mutex_exit(&zv->zv_state_lock);
	if (drop_suspend)
		rw_exit(&zv->zv_suspend_lock);
	if (error == -EINTR) {
		error = -ERESTARTSYS;
		schedule();
	}
	return (SET_ERROR(error));
}

static void
zvol_release(struct gendisk *disk, fmode_t mode)
{
	zvol_state_t *zv;
	boolean_t drop_suspend = B_TRUE;

	rw_enter(&zvol_state_lock, RW_READER);
	zv = disk->private_data;

	mutex_enter(&zv->zv_state_lock);
	ASSERT(zv->zv_open_count > 0);
	/*
	 * make sure zvol is not suspended during last close
	 * (hold zv_suspend_lock) and respect proper lock acquisition
	 * ordering - zv_suspend_lock before zv_state_lock
	 */
	if (zv->zv_open_count == 1) {
		if (!rw_tryenter(&zv->zv_suspend_lock, RW_READER)) {
			mutex_exit(&zv->zv_state_lock);
			rw_enter(&zv->zv_suspend_lock, RW_READER);
			mutex_enter(&zv->zv_state_lock);
			/* check to see if zv_suspend_lock is needed */
			if (zv->zv_open_count != 1) {
				rw_exit(&zv->zv_suspend_lock);
				drop_suspend = B_FALSE;
			}
		}
	} else {
		drop_suspend = B_FALSE;
	}
	rw_exit(&zvol_state_lock);

	ASSERT(MUTEX_HELD(&zv->zv_state_lock));
	ASSERT(zv->zv_open_count != 1 || RW_READ_HELD(&zv->zv_suspend_lock));

	zv->zv_open_count--;
	if (zv->zv_open_count == 0)
		zvol_last_close(zv);

	mutex_exit(&zv->zv_state_lock);

	if (drop_suspend)
		rw_exit(&zv->zv_suspend_lock);
}

/* extent mapping arg */
struct maparg {
	zvol_state_t	*ma_zv;
	uint64_t	ma_blks;
};

/*ARGSUSED*/
static int
zvol_map_block(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
	struct maparg *ma = arg;
	zvol_extent_t *ze;
	int bs = ma->ma_zv->zv_volblocksize;

	if (bp == NULL || BP_IS_HOLE(bp) ||
	    zb->zb_object != ZVOL_OBJ || zb->zb_level != 0)
		return (0);

	VERIFY(!BP_IS_EMBEDDED(bp));

	VERIFY3U(ma->ma_blks, ==, zb->zb_blkid);
	ma->ma_blks++;

	/* Abort immediately if we have encountered gang blocks */
	if (BP_IS_GANG(bp))
		return (SET_ERROR(EFRAGS));

	/*
	 * See if the block is at the end of the previous extent.
	 */
	ze = list_tail(&ma->ma_zv->zv_extents);
	if (ze &&
	    DVA_GET_VDEV(BP_IDENTITY(bp)) == DVA_GET_VDEV(&ze->ze_dva) &&
	    DVA_GET_OFFSET(BP_IDENTITY(bp)) ==
	    DVA_GET_OFFSET(&ze->ze_dva) + ze->ze_nblks * bs) {
		ze->ze_nblks++;
		return (0);
	}

	dprintf_bp(bp, "%s", "next blkptr:");

	/* start a new extent */
	ze = kmem_zalloc(sizeof (zvol_extent_t), KM_SLEEP);
	ze->ze_dva = bp->blk_dva[0];	/* structure assignment */
	ze->ze_nblks = 1;
	list_insert_tail(&ma->ma_zv->zv_extents, ze);
	return (0);
}

static void
zvol_free_extents(zvol_state_t *zv)
{
	zvol_extent_t *ze;

	while ((ze = list_head(&zv->zv_extents)) != NULL) {
		list_remove(&zv->zv_extents, ze);
		kmem_free(ze, sizeof (zvol_extent_t));
	}
}

static int
zvol_get_lbas(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	struct maparg	ma;
	int		err;

	ma.ma_zv = zv;
	ma.ma_blks = 0;
	zvol_free_extents(zv);

	/* commit any in-flight changes before traversing the dataset */
	txg_wait_synced(dmu_objset_pool(os), 0);
	err = traverse_dataset(dmu_objset_ds(os), 0,
	    TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA, zvol_map_block, &ma);
	if (err || ma.ma_blks != (zv->zv_volsize / zv->zv_volblocksize)) {
		zvol_free_extents(zv);
		return (err ? err : EIO);
	}

	return (0);
}

static int
zvol_prealloc(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	uint64_t refd, avail, usedobjs, availobjs;
	uint64_t resid = zv->zv_volsize;
	uint64_t off = 0;

	/* Check the space usage before attempting to allocate the space */
	dmu_objset_space(os, &refd, &avail, &usedobjs, &availobjs);
	if (avail < zv->zv_volsize)
		return (SET_ERROR(ENOSPC));

	/* Free old extents if they exist */
	zvol_free_extents(zv);

	while (resid != 0) {
		int error;
		uint64_t bytes = MIN(resid, SPA_OLD_MAXBLOCKSIZE);

		tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			(void) dmu_free_long_range(os, ZVOL_OBJ, 0, off);
			return (error);
		}
		dmu_prealloc(os, ZVOL_OBJ, off, bytes, tx);
		dmu_tx_commit(tx);
		off += bytes;
		resid -= bytes;
	}
	txg_wait_synced(dmu_objset_pool(os), 0);

	return (0);
}

static int
zfs_mvdev_dump_feature_check(void *arg, dmu_tx_t *tx)
{
	spa_t *spa = dmu_tx_pool(tx)->dp_spa;

	if (spa_feature_is_active(spa, SPA_FEATURE_MULTI_VDEV_CRASH_DUMP))
		return (1);
	return (0);
}

static void
zfs_mvdev_dump_activate_feature_sync(void *arg, dmu_tx_t *tx)
{
	spa_t *spa = dmu_tx_pool(tx)->dp_spa;

	spa_feature_incr(spa, SPA_FEATURE_MULTI_VDEV_CRASH_DUMP, tx);
}

static int
zvol_dump_fini(zvol_state_t *zv)
{
	dmu_tx_t *tx;
	objset_t *os = zv->zv_objset;
	nvlist_t *nv;
	int error = 0;
	uint64_t checksum, compress, refresrv, vbs, dedup;
	uint64_t version = spa_version(dmu_objset_spa(zv->zv_objset));

	/*
	 * Attempt to restore the zvol back to its pre-dumpified state.
	 * This is a best-effort attempt as it's possible that not all
	 * of these properties were initialized during the dumpify process
	 * (i.e. error during zvol_dump_init).
	 */

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	(void) zap_remove(os, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE, tx);
	dmu_tx_commit(tx);

	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_CHECKSUM), 8, 1, &checksum);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_COMPRESSION), 8, 1, &compress);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1, &refresrv);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), 8, 1, &vbs);

	VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_CHECKSUM), checksum);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_COMPRESSION), compress);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), refresrv);
	if (version >= SPA_VERSION_DEDUP &&
	    zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_DEDUP), 8, 1, &dedup) == 0) {
		(void) nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_DEDUP), dedup);
	}
	(void) zfs_set_prop_nvlist(zv->zv_name, ZPROP_SRC_LOCAL,
	    nv, NULL);
	nvlist_free(nv);

	zvol_free_extents(zv);
	zv->zv_flags &= ~ZVOL_DUMPIFIED;
	(void) dmu_free_long_range(os, ZVOL_OBJ, 0, DMU_OBJECT_END);
	/* wait for dmu_free_long_range to actually free the blocks */
	txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
	tx = dmu_tx_create(os);
	dmu_tx_hold_bonus(tx, ZVOL_OBJ);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	if (dmu_object_set_blocksize(os, ZVOL_OBJ, vbs, 0, tx) == 0)
		zv->zv_volblocksize = vbs;
	dmu_tx_commit(tx);

	return (0);
}

static int
zvol_dump_init(zvol_state_t *zv, boolean_t resize)
{
	dmu_tx_t *tx;
	int error;
	objset_t *os = zv->zv_objset;
	spa_t *spa = dmu_objset_spa(os);
	vdev_t *vd = spa->spa_root_vdev;
	nvlist_t *nv = NULL;
	uint64_t version = spa_version(spa);
	uint64_t checksum, compress, refresrv, vbs, dedup;

	ASSERT(MUTEX_HELD(&zv->zv_state_lock));
	ASSERT(vd->vdev_ops == &vdev_root_ops);

	error = dmu_free_long_range(zv->zv_objset, ZVOL_OBJ, 0,
	    DMU_OBJECT_END);
	if (error != 0)
		return (error);
	/* wait for dmu_free_long_range to actually free the blocks */
	txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);

	/*
	 * If the pool on which the dump device is being initialized has more
	 * than one child vdev, check that the MULTI_VDEV_CRASH_DUMP feature is
	 * enabled.  If so, bump that feature's counter to indicate that the
	 * feature is active. We also check the vdev type to handle the
	 * following case:
	 *   # zpool create test raidz disk1 disk2 disk3
	 *   Now have spa_root_vdev->vdev_children == 1 (the raidz vdev),
	 *   the raidz vdev itself has 3 children.
	 */
	if (vd->vdev_children > 1 || vd->vdev_ops == &vdev_raidz_ops) {
		if (!spa_feature_is_enabled(spa,
		    SPA_FEATURE_MULTI_VDEV_CRASH_DUMP))
			return (SET_ERROR(ENOTSUP));
		(void) dsl_sync_task(spa_name(spa),
		    zfs_mvdev_dump_feature_check,
		    zfs_mvdev_dump_activate_feature_sync, NULL,
		    2, ZFS_SPACE_CHECK_RESERVED);
	}

	if (!resize) {
		error = dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION), &compress, NULL);
		if (error == 0) {
			error = dsl_prop_get_integer(zv->zv_name,
			    zfs_prop_to_name(ZFS_PROP_CHECKSUM), &checksum,
			    NULL);
		}
		if (error == 0) {
			error = dsl_prop_get_integer(zv->zv_name,
			    zfs_prop_to_name(ZFS_PROP_REFRESERVATION),
			    &refresrv, NULL);
		}
		if (error == 0) {
			error = dsl_prop_get_integer(zv->zv_name,
			    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &vbs,
			    NULL);
		}
		if (version >= SPA_VERSION_DEDUP && error == 0) {
			error = dsl_prop_get_integer(zv->zv_name,
			    zfs_prop_to_name(ZFS_PROP_DEDUP), &dedup, NULL);
		}
	}
	if (error != 0)
		return (error);

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_hold_bonus(tx, ZVOL_OBJ);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
		return (error);
	}

	/*
	 * If we are resizing the dump device then we only need to
	 * update the refreservation to match the newly updated
	 * zvolsize. Otherwise, we save off the original state of the
	 * zvol so that we can restore them if the zvol is ever undumpified.
	 */
	if (resize) {
		error = zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1,
		    &zv->zv_volsize, tx);
	} else {
		error = zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION), 8, 1,
		    &compress, tx);
		if (error == 0) {
			error = zap_update(os, ZVOL_ZAP_OBJ,
			    zfs_prop_to_name(ZFS_PROP_CHECKSUM), 8, 1,
			    &checksum, tx);
		}
		if (error == 0) {
			error = zap_update(os, ZVOL_ZAP_OBJ,
			    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1,
			    &refresrv, tx);
		}
		if (error == 0) {
			error = zap_update(os, ZVOL_ZAP_OBJ,
			    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), 8, 1,
			    &vbs, tx);
		}
		if (error == 0) {
			error = dmu_object_set_blocksize(
			    os, ZVOL_OBJ, SPA_OLD_MAXBLOCKSIZE, 0, tx);
		}
		if (version >= SPA_VERSION_DEDUP && error == 0) {
			error = zap_update(os, ZVOL_ZAP_OBJ,
			    zfs_prop_to_name(ZFS_PROP_DEDUP), 8, 1,
			    &dedup, tx);
		}
		if (error == 0)
			zv->zv_volblocksize = SPA_OLD_MAXBLOCKSIZE;
	}
	dmu_tx_commit(tx);

	/*
	 * We only need update the zvol's property if we are initializing
	 * the dump area for the first time.
	 */
	if (error == 0 && !resize) {
		/*
		 * If MULTI_VDEV_CRASH_DUMP is active, use the NOPARITY checksum
		 * function.  Otherwise, use the old default -- OFF.
		 */
		checksum = spa_feature_is_active(spa,
		    SPA_FEATURE_MULTI_VDEV_CRASH_DUMP) ? ZIO_CHECKSUM_NOPARITY :
		    ZIO_CHECKSUM_OFF;

		VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 0) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION),
		    ZIO_COMPRESS_OFF) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_CHECKSUM),
		    checksum) == 0);
		if (version >= SPA_VERSION_DEDUP) {
			VERIFY(nvlist_add_uint64(nv,
			    zfs_prop_to_name(ZFS_PROP_DEDUP),
			    ZIO_CHECKSUM_OFF) == 0);
		}

		error = zfs_set_prop_nvlist(zv->zv_name, ZPROP_SRC_LOCAL,
		    nv, NULL);
		nvlist_free(nv);
	}

	/* Allocate the space for the dump */
	if (error == 0)
		error = zvol_prealloc(zv);
	return (error);
}

static int
zvol_dumpify(zvol_state_t *zv)
{
	int error = 0;
	uint64_t dumpsize = 0;
	dmu_tx_t *tx;
	objset_t *os = zv->zv_objset;

	if (zv->zv_flags & ZVOL_RDONLY)
		return (SET_ERROR(EROFS));

	if (zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE,
	    8, 1, &dumpsize) != 0 || dumpsize != zv->zv_volsize) {
		boolean_t resize = (dumpsize > 0);

		if ((error = zvol_dump_init(zv, resize)) != 0) {
			(void) zvol_dump_fini(zv);
			return (error);
		}
	}

	/*
	 * Build up our lba mapping.
	 */
	error = zvol_get_lbas(zv);
	if (error) {
		(void) zvol_dump_fini(zv);
		return (error);
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		(void) zvol_dump_fini(zv);
		return (error);
	}

	zv->zv_flags |= ZVOL_DUMPIFIED;
	error = zap_update(os, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE, 8, 1,
	    &zv->zv_volsize, tx);
	dmu_tx_commit(tx);

	if (error) {
		(void) zvol_dump_fini(zv);
		return (error);
	}

	txg_wait_synced(dmu_objset_pool(os), 0);
	return (0);
}

static int
zvol_ioctl(struct block_device *bdev, fmode_t mode,
    unsigned int cmd, unsigned long arg)
{
	zvol_state_t *zv = bdev->bd_disk->private_data;
	int error = 0;
	zfs_locked_range_t *lr;

	ASSERT3U(zv->zv_open_count, >, 0);

	switch (cmd) {
	case BLKFLSBUF:
		fsync_bdev(bdev);
		invalidate_bdev(bdev);
		rw_enter(&zv->zv_suspend_lock, RW_READER);

		if (!(zv->zv_flags & ZVOL_RDONLY))
			txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);

		rw_exit(&zv->zv_suspend_lock);
		break;

	case BLKZNAME:
		mutex_enter(&zv->zv_state_lock);
		error = copy_to_user((void *)arg, zv->zv_name, MAXNAMELEN);
		mutex_exit(&zv->zv_state_lock);
		break;

	case DKIOCDUMPINIT:
		mutex_enter(&zv->zv_state_lock);
		lr = zfs_rangelock_enter(&zv->zv_rangelock, 0, zv->zv_volsize,
		    RL_WRITER);
		error = zvol_dumpify(zv);
		zfs_rangelock_exit(lr);
		mutex_exit(&zv->zv_state_lock);
		break;

	case DKIOCDUMPFINI:
		if (!(zv->zv_flags & ZVOL_DUMPIFIED))
			break;
		mutex_enter(&zv->zv_state_lock);
		lr = zfs_rangelock_enter(&zv->zv_rangelock, 0, zv->zv_volsize,
		    RL_WRITER);
		error = zvol_dump_fini(zv);
		zfs_rangelock_exit(lr);
		mutex_exit(&zv->zv_state_lock);
		break;

	default:
		error = -ENOTTY;
		break;
	}

	return (SET_ERROR(error));
}

#ifdef CONFIG_COMPAT
static int
zvol_compat_ioctl(struct block_device *bdev, fmode_t mode,
    unsigned cmd, unsigned long arg)
{
	return (zvol_ioctl(bdev, mode, cmd, arg));
}
#else
#define	zvol_compat_ioctl	NULL
#endif

static unsigned int
zvol_check_events(struct gendisk *disk, unsigned int clearing)
{
	unsigned int mask = 0;

	rw_enter(&zvol_state_lock, RW_READER);

	zvol_state_t *zv = disk->private_data;
	if (zv != NULL) {
		mutex_enter(&zv->zv_state_lock);
		mask = zv->zv_changed ? DISK_EVENT_MEDIA_CHANGE : 0;
		zv->zv_changed = 0;
		mutex_exit(&zv->zv_state_lock);
	}

	rw_exit(&zvol_state_lock);

	return (mask);
}

static int
zvol_revalidate_disk(struct gendisk *disk)
{
	rw_enter(&zvol_state_lock, RW_READER);

	zvol_state_t *zv = disk->private_data;
	if (zv != NULL) {
		mutex_enter(&zv->zv_state_lock);
		set_capacity(zv->zv_zso->zvo_disk,
		    zv->zv_volsize >> SECTOR_BITS);
		mutex_exit(&zv->zv_state_lock);
	}

	rw_exit(&zvol_state_lock);

	return (0);
}

int
zvol_update_volsize(zvol_state_t *zv, uint64_t volsize)
{

	revalidate_disk(zv->zv_zso->zvo_disk);
	return (0);
}

static void
zvol_clear_private(zvol_state_t *zv)
{
	/*
	 * Cleared while holding zvol_state_lock as a writer
	 * which will prevent zvol_open() from opening it.
	 */
	zv->zv_zso->zvo_disk->private_data = NULL;
}

/*
 * Provide a simple virtual geometry for legacy compatibility.  For devices
 * smaller than 1 MiB a small head and sector count is used to allow very
 * tiny devices.  For devices over 1 Mib a standard head and sector count
 * is used to keep the cylinders count reasonable.
 */
static int
zvol_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	zvol_state_t *zv = bdev->bd_disk->private_data;
	sector_t sectors;

	ASSERT3U(zv->zv_open_count, >, 0);

	sectors = get_capacity(zv->zv_zso->zvo_disk);

	if (sectors > 2048) {
		geo->heads = 16;
		geo->sectors = 63;
	} else {
		geo->heads = 2;
		geo->sectors = 4;
	}

	geo->start = 0;
	geo->cylinders = sectors / (geo->heads * geo->sectors);

	return (0);
}

/*
 * Find a zvol_state_t given the full major+minor dev_t. If found,
 * return with zv_state_lock taken, otherwise, return (NULL) without
 * taking zv_state_lock.
 */
static zvol_state_t *
zvol_find_by_dev(dev_t dev)
{
	zvol_state_t *zv;

	rw_enter(&zvol_state_lock, RW_READER);
	for (zv = list_head(&zvol_state_list); zv != NULL;
	    zv = list_next(&zvol_state_list, zv)) {
		mutex_enter(&zv->zv_state_lock);
		if (zv->zv_zso->zvo_dev == dev) {
			rw_exit(&zvol_state_lock);
			return (zv);
		}
		mutex_exit(&zv->zv_state_lock);
	}
	rw_exit(&zvol_state_lock);

	return (NULL);
}

void
zvol_validate_dev(zvol_state_t *zv)
{
	ASSERT3U(MINOR(zv->zv_zso->zvo_dev) & ZVOL_MINOR_MASK, ==, 0);
}

static struct kobject *
zvol_probe(dev_t dev, int *part, void *arg)
{
	zvol_state_t *zv;
	struct kobject *kobj;

	zv = zvol_find_by_dev(dev);
	kobj = zv ? get_disk_and_module(zv->zv_zso->zvo_disk) : NULL;
	ASSERT(zv == NULL || MUTEX_HELD(&zv->zv_state_lock));
	if (zv)
		mutex_exit(&zv->zv_state_lock);

	return (kobj);
}

static struct block_device_operations zvol_ops = {
	.open			= zvol_open,
	.release		= zvol_release,
	.ioctl			= zvol_ioctl,
	.compat_ioctl		= zvol_compat_ioctl,
	.check_events		= zvol_check_events,
	.revalidate_disk	= zvol_revalidate_disk,
	.getgeo			= zvol_getgeo,
	.owner			= THIS_MODULE,
};

/*
 * Allocate memory for a new zvol_state_t and setup the required
 * request queue and generic disk structures for the block device.
 */
static zvol_state_t *
zvol_alloc(dev_t dev, const char *name)
{
	zvol_state_t *zv;
	struct zvol_state_os *zso;
	uint64_t volmode;

	if (dsl_prop_get_integer(name, "volmode", &volmode, NULL) != 0)
		return (NULL);

	if (volmode == ZFS_VOLMODE_DEFAULT)
		volmode = zvol_volmode;

	if (volmode == ZFS_VOLMODE_NONE)
		return (NULL);

	zv = kmem_zalloc(sizeof (zvol_state_t), KM_SLEEP);
	zso = kmem_zalloc(sizeof (struct zvol_state_os), KM_SLEEP);
	zv->zv_zso = zso;

	list_link_init(&zv->zv_next);
	mutex_init(&zv->zv_state_lock, NULL, MUTEX_DEFAULT, NULL);

	zso->zvo_queue = blk_generic_alloc_queue(zvol_request, NUMA_NO_NODE);
	if (zso->zvo_queue == NULL)
		goto out_kmem;

	blk_queue_set_write_cache(zso->zvo_queue, B_TRUE, B_TRUE);

	/* Limit read-ahead to a single page to prevent over-prefetching. */
	blk_queue_set_read_ahead(zso->zvo_queue, 1);

	/* Disable write merging in favor of the ZIO pipeline. */
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, zso->zvo_queue);

	zso->zvo_disk = alloc_disk(ZVOL_MINORS);
	if (zso->zvo_disk == NULL)
		goto out_queue;

	zso->zvo_queue->queuedata = zv;
	zso->zvo_dev = dev;
	zv->zv_open_count = 0;
	strlcpy(zv->zv_name, name, MAXNAMELEN);

	zfs_rangelock_init(&zv->zv_rangelock, NULL, NULL);
	rw_init(&zv->zv_suspend_lock, NULL, RW_DEFAULT, NULL);

	list_create(&zv->zv_extents, sizeof (zvol_extent_t),
	    offsetof(zvol_extent_t, ze_node));

	zso->zvo_disk->major = zvol_major;
	zso->zvo_disk->events = DISK_EVENT_MEDIA_CHANGE;

	if (volmode == ZFS_VOLMODE_DEV) {
		/*
		 * ZFS_VOLMODE_DEV disable partitioning on ZVOL devices: set
		 * gendisk->minors = 1 as noted in include/linux/genhd.h.
		 * Also disable extended partition numbers (GENHD_FL_EXT_DEVT)
		 * and suppresses partition scanning (GENHD_FL_NO_PART_SCAN)
		 * setting gendisk->flags accordingly.
		 */
		zso->zvo_disk->minors = 1;
#if defined(GENHD_FL_EXT_DEVT)
		zso->zvo_disk->flags &= ~GENHD_FL_EXT_DEVT;
#endif
#if defined(GENHD_FL_NO_PART_SCAN)
		zso->zvo_disk->flags |= GENHD_FL_NO_PART_SCAN;
#endif
	}
	zso->zvo_disk->first_minor = (dev & MINORMASK);
	zso->zvo_disk->fops = &zvol_ops;
	zso->zvo_disk->private_data = zv;
	zso->zvo_disk->queue = zso->zvo_queue;
	snprintf(zso->zvo_disk->disk_name, DISK_NAME_LEN, "%s%d",
	    ZVOL_DEV_NAME, (dev & MINORMASK));

	return (zv);

out_queue:
	blk_cleanup_queue(zso->zvo_queue);
out_kmem:
	kmem_free(zso, sizeof (struct zvol_state_os));
	kmem_free(zv, sizeof (zvol_state_t));
	return (NULL);
}

/*
 * Cleanup then free a zvol_state_t which was created by zvol_alloc().
 * At this time, the structure is not opened by anyone, is taken off
 * the zvol_state_list, and has its private data set to NULL.
 * The zvol_state_lock is dropped.
 *
 * This function may take many milliseconds to complete (e.g. we've seen
 * it take over 256ms), due to the calls to "blk_cleanup_queue" and
 * "del_gendisk". Thus, consumers need to be careful to account for this
 * latency when calling this function.
 */
static void
zvol_free(zvol_state_t *zv)
{

	ASSERT(!RW_LOCK_HELD(&zv->zv_suspend_lock));
	ASSERT(!MUTEX_HELD(&zv->zv_state_lock));
	ASSERT(zv->zv_open_count == 0);
	ASSERT(zv->zv_zso->zvo_disk->private_data == NULL);

	rw_destroy(&zv->zv_suspend_lock);
	zfs_rangelock_fini(&zv->zv_rangelock);

	del_gendisk(zv->zv_zso->zvo_disk);
	blk_cleanup_queue(zv->zv_zso->zvo_queue);
	put_disk(zv->zv_zso->zvo_disk);

	ida_simple_remove(&zvol_ida,
	    MINOR(zv->zv_zso->zvo_dev) >> ZVOL_MINOR_BITS);

	mutex_destroy(&zv->zv_state_lock);
	dataset_kstats_destroy(&zv->zv_zso->zvo_kstat);

	kmem_free(zv->zv_zso, sizeof (struct zvol_state_os));
	kmem_free(zv, sizeof (zvol_state_t));
}

/*
 * Create a block device minor node and setup the linkage between it
 * and the specified volume.  Once this function returns the block
 * device is live and ready for use.
 */
static int
zvol_os_create_minor(const char *name)
{
	zvol_state_t *zv;
	objset_t *os;
	dmu_object_info_t *doi;
	uint64_t volsize;
	uint64_t len;
	unsigned minor = 0;
	int error = 0;
	int idx;
	uint64_t hash = zvol_name_hash(name);

	if (zvol_inhibit_dev)
		return (0);

	idx = ida_simple_get(&zvol_ida, 0, 0, kmem_flags_convert(KM_SLEEP));
	if (idx < 0)
		return (SET_ERROR(-idx));
	minor = idx << ZVOL_MINOR_BITS;

	zv = zvol_find_by_name_hash(name, hash, RW_NONE);
	if (zv) {
		ASSERT(MUTEX_HELD(&zv->zv_state_lock));
		mutex_exit(&zv->zv_state_lock);
		ida_simple_remove(&zvol_ida, idx);
		return (SET_ERROR(EEXIST));
	}

	doi = kmem_alloc(sizeof (dmu_object_info_t), KM_SLEEP);

	error = dmu_objset_own(name, DMU_OST_ZVOL, B_TRUE, B_TRUE, FTAG, &os);
	if (error)
		goto out_doi;

	error = dmu_object_info(os, ZVOL_OBJ, doi);
	if (error)
		goto out_dmu_objset_disown;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize);
	if (error)
		goto out_dmu_objset_disown;

	zv = zvol_alloc(MKDEV(zvol_major, minor), name);
	if (zv == NULL) {
		error = SET_ERROR(EAGAIN);
		goto out_dmu_objset_disown;
	}
	zv->zv_hash = hash;

	if (dmu_objset_is_snapshot(os))
		zv->zv_flags |= ZVOL_RDONLY;

	zv->zv_volblocksize = doi->doi_data_block_size;
	zv->zv_volsize = volsize;
	zv->zv_objset = os;

	set_capacity(zv->zv_zso->zvo_disk, zv->zv_volsize >> 9);

	blk_queue_max_hw_sectors(zv->zv_zso->zvo_queue,
	    (DMU_MAX_ACCESS / 4) >> 9);
	blk_queue_max_segments(zv->zv_zso->zvo_queue, UINT16_MAX);
	blk_queue_max_segment_size(zv->zv_zso->zvo_queue, UINT_MAX);
	blk_queue_physical_block_size(zv->zv_zso->zvo_queue,
	    (zvol_fake_phys_block_size ? 512 : zv->zv_volblocksize));
	blk_queue_io_opt(zv->zv_zso->zvo_queue, zv->zv_volblocksize);
	blk_queue_max_discard_sectors(zv->zv_zso->zvo_queue,
	    (zvol_max_discard_blocks * zv->zv_volblocksize) >> 9);
	blk_queue_discard_granularity(zv->zv_zso->zvo_queue,
	    zv->zv_volblocksize);
	blk_queue_flag_set(QUEUE_FLAG_DISCARD, zv->zv_zso->zvo_queue);
#ifdef QUEUE_FLAG_NONROT
	blk_queue_flag_set(QUEUE_FLAG_NONROT, zv->zv_zso->zvo_queue);
#endif
#ifdef QUEUE_FLAG_ADD_RANDOM
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, zv->zv_zso->zvo_queue);
#endif
	/* This flag was introduced in kernel version 4.12. */
#ifdef QUEUE_FLAG_SCSI_PASSTHROUGH
	blk_queue_flag_set(QUEUE_FLAG_SCSI_PASSTHROUGH, zv->zv_zso->zvo_queue);
#endif

	if (spa_writeable(dmu_objset_spa(os))) {
		if (zil_replay_disable)
			zil_destroy(dmu_objset_zil(os), B_FALSE);
		else
			zil_replay(os, zv, zvol_replay_vector);
	}
	ASSERT3P(zv->zv_zso->zvo_kstat.dk_kstats, ==, NULL);
	dataset_kstats_create(&zv->zv_zso->zvo_kstat, zv->zv_objset);

	/*
	 * When udev detects the addition of the device it will immediately
	 * invoke blkid(8) to determine the type of content on the device.
	 * Prefetching the blocks commonly scanned by blkid(8) will speed
	 * up this process.
	 */
	len = MIN(MAX(zvol_prefetch_bytes, 0), SPA_MAXBLOCKSIZE);
	if (len > 0) {
		dmu_prefetch(os, ZVOL_OBJ, 0, 0, len, ZIO_PRIORITY_SYNC_READ);
		dmu_prefetch(os, ZVOL_OBJ, 0, volsize - len, len,
		    ZIO_PRIORITY_SYNC_READ);
	}

	zv->zv_objset = NULL;
out_dmu_objset_disown:
	dmu_objset_disown(os, B_TRUE, FTAG);
out_doi:
	kmem_free(doi, sizeof (dmu_object_info_t));

	/*
	 * Keep in mind that once add_disk() is called, the zvol is
	 * announced to the world, and zvol_open()/zvol_release() can
	 * be called at any time. Incidentally, add_disk() itself calls
	 * zvol_open()->zvol_first_open() and zvol_release()->zvol_last_close()
	 * directly as well.
	 */
	if (error == 0) {
		rw_enter(&zvol_state_lock, RW_WRITER);
		zvol_insert(zv);
		rw_exit(&zvol_state_lock);
		add_disk(zv->zv_zso->zvo_disk);
	} else {
		ida_simple_remove(&zvol_ida, idx);
	}

	return (error);
}

static void
zvol_rename_minor(zvol_state_t *zv, const char *newname)
{
	int readonly = get_disk_ro(zv->zv_zso->zvo_disk);

	ASSERT(RW_LOCK_HELD(&zvol_state_lock));
	ASSERT(MUTEX_HELD(&zv->zv_state_lock));

	strlcpy(zv->zv_name, newname, sizeof (zv->zv_name));

	/* move to new hashtable entry  */
	zv->zv_hash = zvol_name_hash(zv->zv_name);
	hlist_del(&zv->zv_hlink);
	hlist_add_head(&zv->zv_hlink, ZVOL_HT_HEAD(zv->zv_hash));

	/*
	 * The block device's read-only state is briefly changed causing
	 * a KOBJ_CHANGE uevent to be issued.  This ensures udev detects
	 * the name change and fixes the symlinks.  This does not change
	 * ZVOL_RDONLY in zv->zv_flags so the actual read-only state never
	 * changes.  This would normally be done using kobject_uevent() but
	 * that is a GPL-only symbol which is why we need this workaround.
	 */
	set_disk_ro(zv->zv_zso->zvo_disk, !readonly);
	set_disk_ro(zv->zv_zso->zvo_disk, readonly);
}

static void
zvol_set_disk_ro_impl(zvol_state_t *zv, int flags)
{

	set_disk_ro(zv->zv_zso->zvo_disk, flags);
}

static void
zvol_set_capacity_impl(zvol_state_t *zv, uint64_t capacity)
{

	set_capacity(zv->zv_zso->zvo_disk, capacity);
}

const static zvol_platform_ops_t zvol_linux_ops = {
	.zv_free = zvol_free,
	.zv_rename_minor = zvol_rename_minor,
	.zv_create_minor = zvol_os_create_minor,
	.zv_update_volsize = zvol_update_volsize,
	.zv_clear_private = zvol_clear_private,
	.zv_is_zvol = zvol_is_zvol_impl,
	.zv_set_disk_ro = zvol_set_disk_ro_impl,
	.zv_set_capacity = zvol_set_capacity_impl,
};

int
zvol_init(void)
{
	int error;
	int threads = MIN(MAX(zvol_threads, 1), 1024);

	error = register_blkdev(zvol_major, ZVOL_DRIVER);
	if (error) {
		printk(KERN_INFO "ZFS: register_blkdev() failed %d\n", error);
		return (error);
	}
	zvol_taskq = taskq_create(ZVOL_DRIVER, threads, maxclsyspri,
	    threads * 2, INT_MAX, TASKQ_PREPOPULATE | TASKQ_DYNAMIC);
	if (zvol_taskq == NULL) {
		unregister_blkdev(zvol_major, ZVOL_DRIVER);
		return (-ENOMEM);
	}
	zvol_init_impl();
	blk_register_region(MKDEV(zvol_major, 0), 1UL << MINORBITS,
	    THIS_MODULE, zvol_probe, NULL, NULL);

	ida_init(&zvol_ida);
	zvol_register_ops(&zvol_linux_ops);
	return (0);
}

void
zvol_fini(void)
{
	zvol_fini_impl();
	blk_unregister_region(MKDEV(zvol_major, 0), 1UL << MINORBITS);
	unregister_blkdev(zvol_major, ZVOL_DRIVER);
	taskq_destroy(zvol_taskq);
	ida_destroy(&zvol_ida);
}

/* BEGIN CSTYLED */
module_param(zvol_inhibit_dev, uint, 0644);
MODULE_PARM_DESC(zvol_inhibit_dev, "Do not create zvol device nodes");

module_param(zvol_major, uint, 0444);
MODULE_PARM_DESC(zvol_major, "Major number for zvol device");

module_param(zvol_threads, uint, 0444);
MODULE_PARM_DESC(zvol_threads, "Max number of threads to handle I/O requests");

module_param(zvol_request_sync, uint, 0644);
MODULE_PARM_DESC(zvol_request_sync, "Synchronously handle bio requests");

module_param(zvol_max_discard_blocks, ulong, 0444);
MODULE_PARM_DESC(zvol_max_discard_blocks, "Max number of blocks to discard");

module_param(zvol_prefetch_bytes, uint, 0644);
MODULE_PARM_DESC(zvol_prefetch_bytes, "Prefetch N bytes at zvol start+end");

module_param(zvol_volmode, uint, 0644);
MODULE_PARM_DESC(zvol_volmode, "Default volmode property value");
/* END CSTYLED */
