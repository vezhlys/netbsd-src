/*	$NetBSD: msdosfs_vnops.c,v 1.113 2024/09/11 00:27:54 perseant Exp $	*/

/*-
 * Copyright (C) 1994, 1995, 1997 Wolfgang Solfrank.
 * Copyright (C) 1994, 1995, 1997 TooLs GmbH.
 * All rights reserved.
 * Original code by Paul Popelka (paulp@uts.amdahl.com) (see below).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Written by Paul Popelka (paulp@uts.amdahl.com)
 *
 * You can do anything you want with this software, just don't say you wrote
 * it, and don't remove this notice.
 *
 * This software is provided "as is".
 *
 * The author supplies this software to be publicly redistributed on the
 * understanding that the author is not responsible for the correct
 * functioning of this software in any circumstances and is not liable for
 * any damages caused by this software.
 *
 * October 1992
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: msdosfs_vnops.c,v 1.113 2024/09/11 00:27:54 perseant Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/resourcevar.h>	/* defines plimit structure in proc struct */
#include <sys/kernel.h>
#include <sys/file.h>		/* define FWRITE ... */
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/signalvar.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/lockf.h>
#include <sys/kauth.h>

#include <miscfs/genfs/genfs.h>
#include <miscfs/specfs/specdev.h> /* XXX */	/* defines v_rdev */

#include <uvm/uvm_extern.h>

#include <fs/msdosfs/bpb.h>
#include <fs/msdosfs/direntry.h>
#include <fs/msdosfs/denode.h>
#include <fs/msdosfs/msdosfsmount.h>
#include <fs/msdosfs/fat.h>

/*
 * Some general notes:
 *
 * In the ufs filesystem the inodes, superblocks, and indirect blocks are
 * read/written using the vnode for the filesystem. Blocks that represent
 * the contents of a file are read/written using the vnode for the file
 * (including directories when they are read/written as files). This
 * presents problems for the dos filesystem because data that should be in
 * an inode (if dos had them) resides in the directory itself.  Since we
 * must update directory entries without the benefit of having the vnode
 * for the directory we must use the vnode for the filesystem.  This means
 * that when a directory is actually read/written (via read, write, or
 * readdir, or seek) we must use the vnode for the filesystem instead of
 * the vnode for the directory as would happen in ufs. This is to insure we
 * retrieve the correct block from the buffer cache since the hash value is
 * based upon the vnode address and the desired block number.
 */

/*
 * Create a regular file. On entry the directory to contain the file being
 * created is locked.  We must release before we return.
 */
int
msdosfs_create(void *v)
{
	struct vop_create_v3_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct denode ndirent;
	struct denode *dep;
	struct denode *pdep = VTODE(ap->a_dvp);
	int error;

#ifdef MSDOSFS_DEBUG
	printf("msdosfs_create(cnp %p, vap %p\n", cnp, ap->a_vap);
#endif

	/*
	 * If this is the root directory and there is no space left we
	 * can't do anything.  This is because the root directory can not
	 * change size.
	 */
	if (pdep->de_StartCluster == MSDOSFSROOT
	    && pdep->de_crap.mlr_fndoffset >= pdep->de_FileSize) {
		error = ENOSPC;
		goto bad;
	}

	/*
	 * Create a directory entry for the file, then call createde() to
	 * have it installed. NOTE: DOS files are always executable.  We
	 * use the absence of the owner write bit to make the file
	 * readonly.
	 */
	memset(&ndirent, 0, sizeof(ndirent));
	if ((error = msdosfs_uniqdosname(pdep, cnp, ndirent.de_Name)) != 0)
		goto bad;

	ndirent.de_Attributes = (ap->a_vap->va_mode & S_IWUSR) ?
				ATTR_ARCHIVE : ATTR_ARCHIVE | ATTR_READONLY;
	ndirent.de_StartCluster = 0;
	ndirent.de_FileSize = 0;
	ndirent.de_dev = pdep->de_dev;
	ndirent.de_devvp = pdep->de_devvp;
	ndirent.de_pmp = pdep->de_pmp;
	ndirent.de_flag = DE_ACCESS | DE_CREATE | DE_UPDATE;
	DETIMES(&ndirent, NULL, NULL, NULL, pdep->de_pmp->pm_gmtoff);
	if ((error = msdosfs_createde(&ndirent, pdep, &pdep->de_crap, &dep,
	    cnp)) != 0)
		goto bad;
	*ap->a_vpp = DETOV(dep);
	cache_enter(ap->a_dvp, *ap->a_vpp, cnp->cn_nameptr, cnp->cn_namelen,
	    cnp->cn_flags);
	return (0);

bad:
	return (error);
}

int
msdosfs_close(void *v)
{
	struct vop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct denode *dep = VTODE(vp);

	mutex_enter(vp->v_interlock);
	if (vrefcnt(vp) > 1)
		DETIMES(dep, NULL, NULL, NULL, dep->de_pmp->pm_gmtoff);
	mutex_exit(vp->v_interlock);
	return (0);
}

static int
msdosfs_check_possible(struct vnode *vp, struct denode *dep, accmode_t accmode)
{

	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the file system.
	 */
	if (accmode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
		default:
			break;
		}
	}

	return 0;
}

static int
msdosfs_check_permitted(struct vnode *vp, struct denode *dep, accmode_t accmode,
    kauth_cred_t cred)
{
	struct msdosfsmount *pmp = dep->de_pmp;
	mode_t file_mode;

	if ((dep->de_Attributes & ATTR_READONLY) == 0)
		file_mode = S_IRWXU|S_IRWXG|S_IRWXO;
	else
		file_mode = S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;

	file_mode &= (vp->v_type == VDIR ? pmp->pm_dirmask : pmp->pm_mask);

	return kauth_authorize_vnode(cred, KAUTH_ACCESS_ACTION(accmode,
	    vp->v_type, file_mode), vp, NULL, genfs_can_access(vp, cred,
	    pmp->pm_uid, pmp->pm_gid, file_mode, NULL, accmode));
}

int
msdosfs_access(void *v)
{
	struct vop_access_args /* {
		struct vnode *a_vp;
		accmode_t a_accmode;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct denode *dep = VTODE(vp);
	int error;

	error = msdosfs_check_possible(vp, dep, ap->a_accmode);
	if (error)
		return error;

	error = msdosfs_check_permitted(vp, dep, ap->a_accmode, ap->a_cred);

	return error;
}

int
msdosfs_getattr(void *v)
{
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		kauth_cred_t a_cred;
	} */ *ap = v;
	struct denode *dep = VTODE(ap->a_vp);
	struct msdosfsmount *pmp = dep->de_pmp;
	struct vattr *vap = ap->a_vap;
	mode_t mode;
	u_long dirsperblk = pmp->pm_BytesPerSec / sizeof(struct direntry);
	ino_t fileid;

	DETIMES(dep, NULL, NULL, NULL, pmp->pm_gmtoff);
	vap->va_fsid = dep->de_dev;
	/*
	 * The following computation of the fileid must be the same as that
	 * used in msdosfs_readdir() to compute d_fileno. If not, pwd
	 * doesn't work.
	 */
	if (dep->de_Attributes & ATTR_DIRECTORY) {
		fileid = cntobn(pmp, (ino_t)dep->de_StartCluster) * dirsperblk;
		if (dep->de_StartCluster == MSDOSFSROOT)
			fileid = 1;
	} else {
		fileid = cntobn(pmp, (ino_t)dep->de_dirclust) * dirsperblk;
		if (dep->de_dirclust == MSDOSFSROOT)
			fileid = roottobn(pmp, 0) * dirsperblk;
		fileid += dep->de_diroffset / sizeof(struct direntry);
	}
	vap->va_fileid = fileid;
	if ((dep->de_Attributes & ATTR_READONLY) == 0)
		mode = S_IRWXU|S_IRWXG|S_IRWXO;
	else
		mode = S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
	vap->va_mode =
	    mode & (ap->a_vp->v_type == VDIR ? pmp->pm_dirmask : pmp->pm_mask);
	vap->va_uid = pmp->pm_uid;
	vap->va_gid = pmp->pm_gid;
	vap->va_nlink = 1;
	vap->va_rdev = 0;
	vap->va_size = ap->a_vp->v_size;
	msdosfs_dos2unixtime(dep->de_MDate, dep->de_MTime, 0, pmp->pm_gmtoff,
	    &vap->va_mtime);
	if (dep->de_pmp->pm_flags & MSDOSFSMNT_LONGNAME) {
		msdosfs_dos2unixtime(dep->de_ADate, 0, 0, pmp->pm_gmtoff,
		    &vap->va_atime);
		msdosfs_dos2unixtime(dep->de_CDate, dep->de_CTime, dep->de_CHun,
		    pmp->pm_gmtoff, &vap->va_ctime);
	} else {
		vap->va_atime = vap->va_mtime;
		vap->va_ctime = vap->va_mtime;
	}
	vap->va_flags = 0;
	if ((dep->de_Attributes & ATTR_ARCHIVE) == 0) {
		vap->va_flags |= SF_ARCHIVED;
		vap->va_mode  |= S_ARCH1;
	}
	vap->va_gen = 0;
	vap->va_blocksize = pmp->pm_bpcluster;
	vap->va_bytes =
	    (dep->de_FileSize + pmp->pm_crbomask) & ~pmp->pm_crbomask;
	vap->va_type = ap->a_vp->v_type;
	return (0);
}

int
msdosfs_setattr(void *v)
{
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		kauth_cred_t a_cred;
	} */ *ap = v;
	int error = 0, de_changed = 0;
	struct denode *dep = VTODE(ap->a_vp);
	struct msdosfsmount *pmp = dep->de_pmp;
	struct vnode *vp  = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	kauth_cred_t cred = ap->a_cred;

#ifdef MSDOSFS_DEBUG
	printf("msdosfs_setattr(): vp %p, vap %p, cred %p\n",
	    ap->a_vp, vap, cred);
#endif
	/*
	 * Note we silently ignore uid or gid changes.
	 */
	if ((vap->va_type != VNON) || (vap->va_nlink != (nlink_t)VNOVAL) ||
	    (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
	    (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
	    (vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL) ||
	    (vap->va_uid != VNOVAL && vap->va_uid != pmp->pm_uid) ||
	    (vap->va_gid != VNOVAL && vap->va_gid != pmp->pm_gid)) {
#ifdef MSDOSFS_DEBUG
		printf("msdosfs_setattr(): returning EINVAL\n");
		printf("    va_type %d, va_nlink %x, va_fsid %"PRIx64", va_fileid %llx\n",
		    vap->va_type, vap->va_nlink, vap->va_fsid,
		    (unsigned long long)vap->va_fileid);
		printf("    va_blocksize %lx, va_rdev %"PRIx64", va_bytes %"PRIx64", va_gen %lx\n",
		    vap->va_blocksize, vap->va_rdev, vap->va_bytes, vap->va_gen);
#endif
		return (EINVAL);
	}
	/*
	 * Silently ignore attributes modifications on directories.
	 */
	if (ap->a_vp->v_type == VDIR)
		return 0;

	if (vap->va_size != VNOVAL) {
		if (vp->v_mount->mnt_flag & MNT_RDONLY) {
			error = EROFS;
			goto bad;
		}
		error = msdosfs_detrunc(dep, (u_long)vap->va_size, 0, cred);
		if (error)
			goto bad;
		de_changed = 1;
	}
	if (vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL) {
		if (vp->v_mount->mnt_flag & MNT_RDONLY) {
			error = EROFS;
			goto bad;
		}
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_TIMES,
		    ap->a_vp, NULL, genfs_can_chtimes(ap->a_vp, cred,
			pmp->pm_uid, vap->va_vaflags));
		if (error)
			goto bad;
		if ((pmp->pm_flags & MSDOSFSMNT_NOWIN95) == 0 &&
		    vap->va_atime.tv_sec != VNOVAL)
			msdosfs_unix2dostime(&vap->va_atime, pmp->pm_gmtoff,
			    &dep->de_ADate, NULL, NULL);
		if (vap->va_mtime.tv_sec != VNOVAL)
			msdosfs_unix2dostime(&vap->va_mtime, pmp->pm_gmtoff,
			    &dep->de_MDate, &dep->de_MTime, NULL);
		dep->de_Attributes |= ATTR_ARCHIVE;
		dep->de_flag |= DE_MODIFIED;
		de_changed = 1;
	}
	/*
	 * DOS files only have the ability to have their writability
	 * attribute set, so we use the owner write bit to set the readonly
	 * attribute.
	 */
	if (vap->va_mode != (mode_t)VNOVAL) {
		if (vp->v_mount->mnt_flag & MNT_RDONLY) {
			error = EROFS;
			goto bad;
		}
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_FLAGS, vp,
		    NULL, genfs_can_chflags(vp, cred, pmp->pm_uid, false));
		if (error)
			goto bad;
		/* We ignore the read and execute bits. */
		if (vap->va_mode & S_IWUSR)
			dep->de_Attributes &= ~ATTR_READONLY;
		else
			dep->de_Attributes |= ATTR_READONLY;
		dep->de_flag |= DE_MODIFIED;
		de_changed = 1;
	}
	/*
	 * Allow the `archived' bit to be toggled.
	 */
	if (vap->va_flags != VNOVAL) {
		if (vp->v_mount->mnt_flag & MNT_RDONLY) {
			error = EROFS;
			goto bad;
		}
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_FLAGS, vp,
		    NULL, genfs_can_chflags(vp, cred, pmp->pm_uid, false));
		if (error)
			goto bad;
		if (vap->va_flags & SF_ARCHIVED)
			dep->de_Attributes &= ~ATTR_ARCHIVE;
		else
			dep->de_Attributes |= ATTR_ARCHIVE;
		dep->de_flag |= DE_MODIFIED;
		de_changed = 1;
	}

	if (de_changed) {
		error = msdosfs_deupdat(dep, 1);
		if (error)
			goto bad;
	}

bad:
	return error;
}

int
msdosfs_read(void *v)
{
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	int error = 0;
	int64_t diff;
	int blsize;
	long n;
	long on;
	daddr_t lbn;
	vsize_t bytelen;
	struct buf *bp;
	struct vnode *vp = ap->a_vp;
	struct denode *dep = VTODE(vp);
	struct msdosfsmount *pmp = dep->de_pmp;
	struct uio *uio = ap->a_uio;

	/*
	 * If they didn't ask for any data, then we are done.
	 */

	if (uio->uio_resid == 0)
		return (0);
	if (uio->uio_offset < 0)
		return (EINVAL);
	if (uio->uio_offset >= dep->de_FileSize)
		return (0);

	if (vp->v_type == VREG) {
		const int advice = IO_ADV_DECODE(ap->a_ioflag);

		while (uio->uio_resid > 0) {
			bytelen = MIN(dep->de_FileSize - uio->uio_offset,
				      uio->uio_resid);

			if (bytelen == 0)
				break;
			error = ubc_uiomove(&vp->v_uobj, uio, bytelen, advice,
			    UBC_READ | UBC_PARTIALOK | UBC_VNODE_FLAGS(vp));
			if (error)
				break;
		}
		dep->de_flag |= DE_ACCESS;
		goto out;
	}

	/* this loop is only for directories now */
	do {
		lbn = de_cluster(pmp, uio->uio_offset);
		on = uio->uio_offset & pmp->pm_crbomask;
		n = MIN(pmp->pm_bpcluster - on, uio->uio_resid);
		if (uio->uio_offset >= dep->de_FileSize) {
			return (0);
		}
		/* file size (and hence diff) may be up to 4GB */
		diff = dep->de_FileSize - uio->uio_offset;
		if (diff < n)
			n = (long) diff;

		/* convert cluster # to sector # */
		error = msdosfs_pcbmap(dep, lbn, &lbn, 0, &blsize);
		if (error)
			goto bad;

		/*
		 * If we are operating on a directory file then be sure to
		 * do i/o with the vnode for the filesystem instead of the
		 * vnode for the directory.
		 */
		error = bread(pmp->pm_devvp, de_bn2kb(pmp, lbn), blsize,
		    0, &bp);
		if (error) {
			goto bad;
		}
		n = MIN(n, pmp->pm_bpcluster - bp->b_resid);
		error = uiomove((char *)bp->b_data + on, (int) n, uio);
		brelse(bp, 0);
	} while (error == 0 && uio->uio_resid > 0 && n != 0);

out:
	if ((ap->a_ioflag & IO_SYNC) == IO_SYNC) {
		int uerror;

		uerror = msdosfs_deupdat(dep, 1);
		if (error == 0)
			error = uerror;
	}
bad:
	return (error);
}

/*
 * Write data to a file or directory.
 */
int
msdosfs_write(void *v)
{
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		kauth_cred_t a_cred;
	} */ *ap = v;
	int resid;
	int error = 0;
	int ioflag = ap->a_ioflag;
	u_long osize;
	u_long count;
	vsize_t bytelen;
	off_t oldoff;
	size_t rem;
	struct uio *uio = ap->a_uio;
	struct vnode *vp = ap->a_vp;
	struct denode *dep = VTODE(vp);
	struct msdosfsmount *pmp = dep->de_pmp;
	kauth_cred_t cred = ap->a_cred;
	bool async;

#ifdef MSDOSFS_DEBUG
	printf("msdosfs_write(vp %p, uio %p, ioflag %x, cred %p\n",
	    vp, uio, ioflag, cred);
	printf("msdosfs_write(): diroff %lu, dirclust %lu, startcluster %lu\n",
	    dep->de_diroffset, dep->de_dirclust, dep->de_StartCluster);
#endif

	switch (vp->v_type) {
	case VREG:
		if (ioflag & IO_APPEND)
			uio->uio_offset = dep->de_FileSize;
		break;
	case VDIR:
		return EISDIR;
	default:
		panic("msdosfs_write(): bad file type");
	}

	if (uio->uio_offset < 0)
		return (EINVAL);

	if (uio->uio_resid == 0)
		return (0);

	/* Don't bother to try to write files larger than the fs limit */
	if (uio->uio_offset + uio->uio_resid > MSDOSFS_FILESIZE_MAX)
		return (EFBIG);

	/*
	 * If the offset we are starting the write at is beyond the end of
	 * the file, then they've done a seek.  Unix filesystems allow
	 * files with holes in them, DOS doesn't so we must fill the hole
	 * with zeroed blocks.
	 */
	if (uio->uio_offset > dep->de_FileSize) {
		if ((error = msdosfs_deextend(dep, uio->uio_offset,
		    cred)) != 0) {
			return (error);
		}
	}

	/*
	 * Remember some values in case the write fails.
	 */
	async = vp->v_mount->mnt_flag & MNT_ASYNC;
	resid = uio->uio_resid;
	osize = dep->de_FileSize;

	/*
	 * If we write beyond the end of the file, extend it to its ultimate
	 * size ahead of the time to hopefully get a contiguous area.
	 */
	if (uio->uio_offset + resid > osize) {
		count = de_clcount(pmp, uio->uio_offset + resid) -
			de_clcount(pmp, osize);
		if ((error = msdosfs_extendfile(dep, count, NULL, NULL, 0)))
			goto errexit;

		dep->de_FileSize = uio->uio_offset + resid;
		/* hint uvm to not read in extended part */
		uvm_vnp_setwritesize(vp, dep->de_FileSize);
		/* zero out the remainder of the last page */
		rem = round_page(dep->de_FileSize) - dep->de_FileSize;
		if (rem > 0)
			ubc_zerorange(&vp->v_uobj, (off_t)dep->de_FileSize,
			    rem, UBC_VNODE_FLAGS(vp));
	}

	do {
		oldoff = uio->uio_offset;
		bytelen = uio->uio_resid;

		error = ubc_uiomove(&vp->v_uobj, uio, bytelen,
		    IO_ADV_DECODE(ioflag), UBC_WRITE | UBC_VNODE_FLAGS(vp));
		if (error)
			break;

		/*
		 * flush what we just wrote if necessary.
		 * XXXUBC simplistic async flushing.
		 */

		if (!async && oldoff >> 16 != uio->uio_offset >> 16) {
			rw_enter(vp->v_uobj.vmobjlock, RW_WRITER);
			error = VOP_PUTPAGES(vp, (oldoff >> 16) << 16,
			    (uio->uio_offset >> 16) << 16,
			    PGO_CLEANIT | PGO_LAZY);
		}
	} while (error == 0 && uio->uio_resid > 0);

	/* set final size */
	uvm_vnp_setsize(vp, dep->de_FileSize);
	if (error == 0 && ioflag & IO_SYNC) {
		rw_enter(vp->v_uobj.vmobjlock, RW_WRITER);
		error = VOP_PUTPAGES(vp, trunc_page(oldoff),
		    round_page(oldoff + bytelen), PGO_CLEANIT | PGO_SYNCIO);
	}
	dep->de_flag |= DE_UPDATE;

	/*
	 * If the write failed and they want us to, truncate the file back
	 * to the size it was before the write was attempted.
	 */
errexit:
	if (error) {
		msdosfs_detrunc(dep, osize, ioflag & IO_SYNC, NOCRED);
		uio->uio_offset -= resid - uio->uio_resid;
		uio->uio_resid = resid;
	} else if ((ioflag & IO_SYNC) == IO_SYNC)
		error = msdosfs_deupdat(dep, 1);
	KASSERT(vp->v_size == dep->de_FileSize);
	return (error);
}

int
msdosfs_update(struct vnode *vp, const struct timespec *acc,
    const struct timespec *mod, int flags)
{
	struct buf *bp;
	struct direntry *dirp;
	struct denode *dep;
	int error;

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (0);
	dep = VTODE(vp);
	DETIMES(dep, acc, mod, NULL, dep->de_pmp->pm_gmtoff);
	if ((dep->de_flag & DE_MODIFIED) == 0)
		return (0);
	dep->de_flag &= ~DE_MODIFIED;
	if (dep->de_Attributes & ATTR_DIRECTORY)
		return (0);
	if (dep->de_refcnt <= 0)
		return (0);
	error = msdosfs_readde(dep, &bp, &dirp);
	if (error)
		return (error);
	DE_EXTERNALIZE(dirp, dep);
	if (flags & (UPDATE_WAIT|UPDATE_DIROP))
		return (bwrite(bp));
	else {
		bdwrite(bp);
		return (0);
	}
}

int
msdosfs_remove(void *v)
{
	struct vop_remove_v3_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		nlink_t ctx_vp_new_nlink;
	} */ *ap = v;
	struct denode *dep = VTODE(ap->a_vp);
	struct denode *ddep = VTODE(ap->a_dvp);
	int error;

	if (ap->a_vp->v_type == VDIR)
		error = EPERM;
	else
		error = msdosfs_removede(ddep, dep, &ddep->de_crap);
#ifdef MSDOSFS_DEBUG
	printf("msdosfs_remove(), dep %p, usecount %d\n",
		dep, vrefcnt(ap->a_vp));
#endif
	if (ddep == dep)
		vrele(ap->a_vp);
	else
		vput(ap->a_vp);	/* causes msdosfs_inactive() to be called
				 * via vrele() */

	return (error);
}

static const struct {
	struct direntry dot;
	struct direntry dotdot;
} dosdirtemplate = {
	{	".       ", "   ",			/* the . entry */
		ATTR_DIRECTORY,				/* file attribute */
		0,	 				/* reserved */
		0, { 0, 0 }, { 0, 0 },			/* create time & date */
		{ 0, 0 },				/* access date */
		{ 0, 0 },				/* high bits of start cluster */
		{ 210, 4 }, { 210, 4 },			/* modify time & date */
		{ 0, 0 },				/* startcluster */
		{ 0, 0, 0, 0 } 				/* filesize */
	},
	{	"..      ", "   ",			/* the .. entry */
		ATTR_DIRECTORY,				/* file attribute */
		0,	 				/* reserved */
		0, { 0, 0 }, { 0, 0 },			/* create time & date */
		{ 0, 0 },				/* access date */
		{ 0, 0 },				/* high bits of start cluster */
		{ 210, 4 }, { 210, 4 },			/* modify time & date */
		{ 0, 0 },				/* startcluster */
		{ 0, 0, 0, 0 }				/* filesize */
	}
};

int
msdosfs_mkdir(void *v)
{
	struct vop_mkdir_v3_args /* {
		struct vnode *a_dvp;
		struvt vnode **a_vpp;
		struvt componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap = v;
	struct componentname *cnp = ap->a_cnp;
	struct denode ndirent;
	struct denode *dep;
	struct denode *pdep = VTODE(ap->a_dvp);
	int error;
	int bn;
	u_long newcluster, pcl;
	daddr_t lbn;
	struct direntry *denp;
	struct msdosfsmount *pmp = pdep->de_pmp;
	struct buf *bp;
	int async = pdep->de_pmp->pm_mountp->mnt_flag & MNT_ASYNC;

	/*
	 * If this is the root directory and there is no space left we
	 * can't do anything.  This is because the root directory can not
	 * change size.
	 */
	if (pdep->de_StartCluster == MSDOSFSROOT
	    && pdep->de_crap.mlr_fndoffset >= pdep->de_FileSize) {
		error = ENOSPC;
		goto bad2;
	}

	/*
	 * Allocate a cluster to hold the about to be created directory.
	 */
	error = msdosfs_clusteralloc(pmp, 0, 1, &newcluster, NULL);
	if (error)
		goto bad2;

	memset(&ndirent, 0, sizeof(ndirent));
	ndirent.de_pmp = pmp;
	ndirent.de_flag = DE_ACCESS | DE_CREATE | DE_UPDATE;
	DETIMES(&ndirent, NULL, NULL, NULL, pmp->pm_gmtoff);

	/*
	 * Now fill the cluster with the "." and ".." entries. And write
	 * the cluster to disk.  This way it is there for the parent
	 * directory to be pointing at if there were a crash.
	 */
	bn = cntobn(pmp, newcluster);
	lbn = de_bn2kb(pmp, bn);
	/* always succeeds */
	bp = getblk(pmp->pm_devvp, lbn, pmp->pm_bpcluster, 0, 0);
	memset(bp->b_data, 0, pmp->pm_bpcluster);
	memcpy(bp->b_data, &dosdirtemplate, sizeof dosdirtemplate);
	denp = (struct direntry *)bp->b_data;
	putushort(denp[0].deStartCluster, newcluster);
	putushort(denp[0].deCDate, ndirent.de_CDate);
	putushort(denp[0].deCTime, ndirent.de_CTime);
	denp[0].deCHundredth = ndirent.de_CHun;
	putushort(denp[0].deADate, ndirent.de_ADate);
	putushort(denp[0].deMDate, ndirent.de_MDate);
	putushort(denp[0].deMTime, ndirent.de_MTime);
	pcl = pdep->de_StartCluster;
	if (FAT32(pmp) && pcl == pmp->pm_rootdirblk)
		pcl = 0;
	putushort(denp[1].deStartCluster, pcl);
	putushort(denp[1].deCDate, ndirent.de_CDate);
	putushort(denp[1].deCTime, ndirent.de_CTime);
	denp[1].deCHundredth = ndirent.de_CHun;
	putushort(denp[1].deADate, ndirent.de_ADate);
	putushort(denp[1].deMDate, ndirent.de_MDate);
	putushort(denp[1].deMTime, ndirent.de_MTime);
	if (FAT32(pmp)) {
		putushort(denp[0].deHighClust, newcluster >> 16);
		putushort(denp[1].deHighClust, pdep->de_StartCluster >> 16);
	} else {
		putushort(denp[0].deHighClust, 0);
		putushort(denp[1].deHighClust, 0);
	}

	if (async)
		bdwrite(bp);
	else if ((error = bwrite(bp)) != 0)
		goto bad;

	/*
	 * Now build up a directory entry pointing to the newly allocated
	 * cluster.  This will be written to an empty slot in the parent
	 * directory.
	 */
	if ((error = msdosfs_uniqdosname(pdep, cnp, ndirent.de_Name)) != 0)
		goto bad;

	ndirent.de_Attributes = ATTR_DIRECTORY;
	ndirent.de_StartCluster = newcluster;
	ndirent.de_FileSize = 0;
	ndirent.de_dev = pdep->de_dev;
	ndirent.de_devvp = pdep->de_devvp;
	if ((error = msdosfs_createde(&ndirent, pdep, &pdep->de_crap, &dep,
	    cnp)) != 0)
		goto bad;
	*ap->a_vpp = DETOV(dep);
	return (0);

bad:
	msdosfs_clusterfree(pmp, newcluster, NULL);
bad2:
	return (error);
}

int
msdosfs_rmdir(void *v)
{
	struct vop_rmdir_v2_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	struct denode *ip, *dp;
	int error;

	ip = VTODE(vp);
	dp = VTODE(dvp);
	/*
	 * No rmdir "." please.
	 */
	if (dp == ip) {
		vrele(vp);
		return (EINVAL);
	}
	/*
	 * Verify the directory is empty (and valid).
	 * (Rmdir ".." won't be valid since
	 *  ".." will contain a reference to
	 *  the current directory and thus be
	 *  non-empty.)
	 */
	error = 0;
	if (!msdosfs_dosdirempty(ip) || ip->de_flag & DE_RENAME) {
		error = ENOTEMPTY;
		goto out;
	}
	/*
	 * Delete the entry from the directory.  For dos filesystems this
	 * gets rid of the directory entry on disk, the in memory copy
	 * still exists but the de_refcnt is <= 0.  This prevents it from
	 * being found by deget().  When the vput() on dep is done we give
	 * up access and eventually msdosfs_reclaim() will be called which
	 * will remove it from the denode cache.
	 */
	if ((error = msdosfs_removede(dp, ip, &dp->de_crap)) != 0)
		goto out;
	/*
	 * This is where we decrement the link count in the parent
	 * directory.  Since dos filesystems don't do this we just purge
	 * the name cache and let go of the parent directory denode.
	 */
	cache_purge(dvp);
	/*
	 * Truncate the directory that is being deleted.
	 */
	error = msdosfs_detrunc(ip, (u_long)0, IO_SYNC, cnp->cn_cred);
	cache_purge(vp);
out:
	vput(vp);
	return (error);
}

int
msdosfs_readdir(void *v)
{
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		kauth_cred_t a_cred;
		int *a_eofflag;
		off_t **a_cookies;
		int *a_ncookies;
	} */ *ap = v;
	int error = 0;
	int diff;
	long n;
	int blsize;
	long on;
	long lost;
	long count;
	u_long cn;
	ino_t fileno;
	u_long dirsperblk;
	long bias = 0;
	daddr_t bn, lbn;
	struct buf *bp;
	struct denode *dep = VTODE(ap->a_vp);
	struct msdosfsmount *pmp = dep->de_pmp;
	struct direntry *dentp;
	struct dirent *dirbuf;
	struct uio *uio = ap->a_uio;
	off_t *cookies = NULL;
	int ncookies = 0, nc = 0;
	off_t offset, uio_off;
	int chksum = -1;
	uint16_t namlen;

#ifdef MSDOSFS_DEBUG
	printf("msdosfs_readdir(): vp %p, uio %p, cred %p, eofflagp %p\n",
	    ap->a_vp, uio, ap->a_cred, ap->a_eofflag);
#endif

	/*
	 * msdosfs_readdir() won't operate properly on regular files since
	 * it does i/o only with the filesystem vnode, and hence can
	 * retrieve the wrong block from the buffer cache for a plain file.
	 * So, fail attempts to readdir() on a plain file.
	 */
	if ((dep->de_Attributes & ATTR_DIRECTORY) == 0)
		return (ENOTDIR);

	/*
	 * If the user buffer is smaller than the size of one dos directory
	 * entry or the file offset is not a multiple of the size of a
	 * directory entry, then we fail the read.
	 */
	count = uio->uio_resid & ~(sizeof(struct direntry) - 1);
	offset = uio->uio_offset;
	if (count < sizeof(struct direntry) ||
	    (offset & (sizeof(struct direntry) - 1)))
		return (EINVAL);
	lost = uio->uio_resid - count;
	uio->uio_resid = count;
	uio_off = uio->uio_offset;
	

	/* Allocate a temporary dirent buffer. */
	dirbuf = malloc(sizeof(struct dirent), M_MSDOSFSTMP, M_WAITOK | M_ZERO);

	if (ap->a_ncookies) {
		nc = uio->uio_resid / _DIRENT_MINSIZE((struct dirent *)0);
		cookies = malloc(nc * sizeof (off_t), M_TEMP, M_WAITOK);
		*ap->a_cookies = cookies;
	}

	dirsperblk = pmp->pm_BytesPerSec / sizeof(struct direntry);

	/*
	 * If they are reading from the root directory then, we simulate
	 * the . and .. entries since these don't exist in the root
	 * directory.  We also set the offset bias to make up for having to
	 * simulate these entries. By this I mean that at file offset 64 we
	 * read the first entry in the root directory that lives on disk.
	 */
	if (dep->de_StartCluster == MSDOSFSROOT
	    || (FAT32(pmp) && dep->de_StartCluster == pmp->pm_rootdirblk)) {
#if 0
		printf("msdosfs_readdir(): going after . or .. in root dir, "
		    "offset %" PRIu64 "\n", offset);
#endif
		bias = 2 * sizeof(struct direntry);
		if (offset < bias) {
			for (n = (int)offset / sizeof(struct direntry);
			     n < 2; n++) {
				if (FAT32(pmp))
					dirbuf->d_fileno = cntobn(pmp,
					     (ino_t)pmp->pm_rootdirblk)
					     * dirsperblk;
				else
					dirbuf->d_fileno = 1;
				dirbuf->d_type = DT_DIR;
				switch (n) {
				case 0:
					dirbuf->d_namlen = 1;
					strlcpy(dirbuf->d_name, ".",
					    sizeof(dirbuf->d_name));
					break;
				case 1:
					dirbuf->d_namlen = 2;
					strlcpy(dirbuf->d_name, "..",
					    sizeof(dirbuf->d_name));
					break;
				}
				dirbuf->d_reclen = _DIRENT_SIZE(dirbuf);
				if (uio->uio_resid < dirbuf->d_reclen)
					goto out;
				error = uiomove(dirbuf, dirbuf->d_reclen, uio);
				if (error)
					goto out;
				offset += sizeof(struct direntry);
				uio_off = offset;
				if (cookies) {
					*cookies++ = offset;
					ncookies++;
					if (ncookies >= nc)
						goto out;
				}
			}
		}
	}

	while (uio->uio_resid > 0) {
		lbn = de_cluster(pmp, offset - bias);
		on = (offset - bias) & pmp->pm_crbomask;
		n = MIN(pmp->pm_bpcluster - on, uio->uio_resid);
		diff = dep->de_FileSize - (offset - bias);
		if (diff <= 0)
			break;
		n = MIN(n, diff);
		if ((error = msdosfs_pcbmap(dep, lbn, &bn, &cn, &blsize)) != 0)
			break;
		error = bread(pmp->pm_devvp, de_bn2kb(pmp, bn), blsize,
		    0, &bp);
		if (error) {
			goto bad;
		}
		n = MIN(n, blsize - bp->b_resid);

		/*
		 * Convert from dos directory entries to fs-independent
		 * directory entries.
		 */
		for (dentp = (struct direntry *)((char *)bp->b_data + on);
		     (char *)dentp < (char *)bp->b_data + on + n;
		     dentp++, offset += sizeof(struct direntry)) {
#if 0

			printf("rd: dentp %08x prev %08x crnt %08x deName %02x attr %02x\n",
			    dentp, prev, crnt, dentp->deName[0], dentp->deAttributes);
#endif
			/*
			 * If this is an unused entry, we can stop.
			 */
			if (dentp->deName[0] == SLOT_EMPTY) {
				brelse(bp, 0);
				goto out;
			}
			/*
			 * Skip deleted entries.
			 */
			if (dentp->deName[0] == SLOT_DELETED) {
				chksum = -1;
				continue;
			}

			/*
			 * Handle Win95 long directory entries
			 */
			if (dentp->deAttributes == ATTR_WIN95) {
				if (pmp->pm_flags & MSDOSFSMNT_SHORTNAME)
					continue;
				chksum =
				    msdosfs_win2unixfn((struct winentry *)dentp,
				    dirbuf, chksum, &namlen,
				    pmp->pm_flags & MSDOSFSMNT_UTF8);
				if (chksum != -1)
					dirbuf->d_namlen = namlen;
				continue;
			}

			/*
			 * Skip volume labels
			 */
			if (dentp->deAttributes & ATTR_VOLUME) {
				chksum = -1;
				continue;
			}
			/*
			 * This computation of d_fileno must match
			 * the computation of va_fileid in
			 * msdosfs_getattr.
			 */
			if (dentp->deAttributes & ATTR_DIRECTORY) {
				fileno = getushort(dentp->deStartCluster);
				if (FAT32(pmp))
					fileno |= ((ino_t)getushort(dentp->deHighClust)) << 16;
				/* if this is the root directory */
				if (fileno == MSDOSFSROOT)
					if (FAT32(pmp))
						fileno = cntobn(pmp,
						    (ino_t)pmp->pm_rootdirblk)
						    * dirsperblk;
					else
						fileno = 1;
				else
					fileno = cntobn(pmp, fileno) * dirsperblk;
				dirbuf->d_fileno = fileno;
				dirbuf->d_type = DT_DIR;
			} else {
				dirbuf->d_fileno =
				    offset / sizeof(struct direntry);
				dirbuf->d_type = DT_REG;
			}
			if (chksum != msdosfs_winChksum(dentp->deName)) {
				char deName[11];

				memcpy(deName, dentp->deName,
				       sizeof dentp->deName);
				memcpy(deName + 8, dentp->deExtension,
				       sizeof dentp->deExtension);
				assert(sizeof(deName) == sizeof(dentp->deName) +
					sizeof(dentp->deExtension));
				dirbuf->d_namlen =
				    msdosfs_dos2unixfn(deName,
				        (u_char *)dirbuf->d_name,
				        pmp->pm_flags & MSDOSFSMNT_SHORTNAME);
			} else
				dirbuf->d_name[dirbuf->d_namlen] = 0;
			namlen = dirbuf->d_namlen;
			chksum = -1;
			dirbuf->d_reclen = _DIRENT_SIZE(dirbuf);
			if (uio->uio_resid < dirbuf->d_reclen) {
				brelse(bp, 0);
				goto out;
			}
			error = uiomove(dirbuf, dirbuf->d_reclen, uio);
			if (error) {
				brelse(bp, 0);
				goto out;
			}
			uio_off = offset + sizeof(struct direntry);
			if (cookies) {
				*cookies++ = offset + sizeof(struct direntry);
				ncookies++;
				if (ncookies >= nc) {
					brelse(bp, 0);
					goto out;
				}
			}
		}
		brelse(bp, 0);
	}

out:
	uio->uio_offset = uio_off;
	uio->uio_resid += lost;
	if (dep->de_FileSize - (offset - bias) <= 0)
		*ap->a_eofflag = 1;
	else
		*ap->a_eofflag = 0;

	if (ap->a_ncookies) {
		if (error) {
			free(*ap->a_cookies, M_TEMP);
			*ap->a_ncookies = 0;
			*ap->a_cookies = NULL;
		} else
			*ap->a_ncookies = ncookies;
	}

bad:
	free(dirbuf, M_MSDOSFSTMP);
	return (error);
}

/*
 * vp  - address of vnode file the file
 * bn  - which cluster we are interested in mapping to a filesystem block number.
 * vpp - returns the vnode for the block special file holding the filesystem
 *	 containing the file of interest
 * bnp - address of where to return the filesystem relative block number
 */
int
msdosfs_bmap(void *v)
{
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap = v;
	struct denode *dep = VTODE(ap->a_vp);
	int run, maxrun;
	daddr_t runbn;
	int status;

	if (ap->a_vpp != NULL)
		*ap->a_vpp = dep->de_devvp;
	if (ap->a_bnp == NULL)
		return (0);
	status = msdosfs_pcbmap(dep, ap->a_bn, ap->a_bnp, 0, 0);

	/*
	 * From FreeBSD:
	 * A little kludgy, but we loop calling pcbmap until we
	 * reach the end of the contiguous piece, or reach MAXPHYS.
	 * Since it reduces disk I/Os, the "wasted" CPU is put to
	 * good use (4 to 5 fold sequential read I/O improvement on USB
	 * drives).
	 */
	if (ap->a_runp != NULL) {
		/* taken from ufs_bmap */
		maxrun = ulmin(MAXPHYS / dep->de_pmp->pm_bpcluster - 1,
			       dep->de_pmp->pm_maxcluster - ap->a_bn);
		for (run = 1; run <= maxrun; run++) {
			if (msdosfs_pcbmap(dep, ap->a_bn + run, &runbn, NULL,
			    NULL) != 0 || runbn !=
			            *ap->a_bnp + de_cn2bn(dep->de_pmp, run))
				break;
		}
		*ap->a_runp = run - 1;
	}

	/*
	 * We need to scale *ap->a_bnp by sector_size/DEV_BSIZE
	 */
	*ap->a_bnp = de_bn2kb(dep->de_pmp, *ap->a_bnp);
	return status;
}

int
msdosfs_strategy(void *v)
{
	struct vop_strategy_args /* {
		struct vnode *a_vp;
		struct buf *a_bp;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct buf *bp = ap->a_bp;
	struct denode *dep = VTODE(bp->b_vp);
	int error = 0;

	if (vp->v_type == VBLK || vp->v_type == VCHR)
		panic("msdosfs_strategy: spec");
	/*
	 * If we don't already know the filesystem relative block number
	 * then get it using pcbmap().  If pcbmap() returns the block
	 * number as -1 then we've got a hole in the file.  DOS filesystems
	 * don't allow files with holes, so we shouldn't ever see this.
	 */
	if (bp->b_blkno == bp->b_lblkno) {
		error = msdosfs_pcbmap(dep, de_bn2cn(dep->de_pmp, bp->b_lblkno),
			       &bp->b_blkno, 0, 0);
		if (error)
			bp->b_blkno = -1;
		if (bp->b_blkno == -1)
			clrbuf(bp);
		else
			bp->b_blkno = de_bn2kb(dep->de_pmp, bp->b_blkno);
	}
	if (bp->b_blkno == -1) {
		biodone(bp);
		return (error);
	}

	/*
	 * Read/write the block from/to the disk that contains the desired
	 * file block.
	 */

	vp = dep->de_devvp;
	return (VOP_STRATEGY(vp, bp));
}

int
msdosfs_print(void *v)
{
	struct vop_print_args /* {
		struct vnode *vp;
	} */ *ap = v;
	struct denode *dep = VTODE(ap->a_vp);

	printf(
	    "tag VT_MSDOSFS, startcluster %ld, dircluster %ld, diroffset %ld ",
	    dep->de_StartCluster, dep->de_dirclust, dep->de_diroffset);
	printf(" dev %llu, %llu ", (unsigned long long)major(dep->de_dev),
	    (unsigned long long)minor(dep->de_dev));
	printf("\n");
	return (0);
}

int
msdosfs_advlock(void *v)
{
	struct vop_advlock_args /* {
		struct vnode *a_vp;
		void *a_id;
		int a_op;
		struct flock *a_fl;
		int a_flags;
	} */ *ap = v;
	struct denode *dep = VTODE(ap->a_vp);

	return lf_advlock(ap, &dep->de_lockf, dep->de_FileSize);
}

int
msdosfs_pathconf(void *v)
{
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
	} */ *ap = v;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = 1;
		return (0);
	case _PC_NAME_MAX:
		*ap->a_retval = ap->a_vp->v_mount->mnt_stat.f_namemax;
		return (0);
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return (0);
	case _PC_SYNC_IO:
		*ap->a_retval = 1;
		return (0);
	case _PC_FILESIZEBITS:
		*ap->a_retval = 32;
		return (0);
	default:
		return genfs_pathconf(ap);
	}
	/* NOTREACHED */
}

/*
 * Flush the blocks of a file to disk.
 *
 * This function is worthless for vnodes that represent directories. Maybe we
 * could just do a sync if they try an fsync on a directory file.
 */
int
msdosfs_fsync(void *v)
{
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		kauth_cred_t a_cred;
		int a_flags;
		off_t offlo;
		off_t offhi;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	int wait;
	int error;

	wait = (ap->a_flags & FSYNC_WAIT) != 0;
	error = vflushbuf(vp, ap->a_flags);
	if (error == 0 && (ap->a_flags & FSYNC_DATAONLY) == 0)
		error = msdosfs_update(vp, NULL, NULL, wait ? UPDATE_WAIT : 0);

	if (error == 0 && ap->a_flags & FSYNC_CACHE) {
		struct denode *dep = VTODE(vp);
		struct vnode *devvp = dep->de_devvp;

		int l = 0;
		error = VOP_IOCTL(devvp, DIOCCACHESYNC, &l, FWRITE,
					  curlwp->l_cred);
	}

	return (error);
}

void
msdosfs_detimes(struct denode *dep, const struct timespec *acc,
    const struct timespec *mod, const struct timespec *cre, int gmtoff)
{
	struct timespec *ts = NULL, tsb;

	KASSERT(dep->de_flag & (DE_UPDATE | DE_CREATE | DE_ACCESS));
	/* XXX just call getnanotime early and use result if needed? */
	dep->de_flag |= DE_MODIFIED;
	if (dep->de_flag & DE_UPDATE) {
		if (mod == NULL) {
			getnanotime(&tsb);
			mod = ts = &tsb;
		}
		msdosfs_unix2dostime(mod, gmtoff, &dep->de_MDate,
		    &dep->de_MTime, NULL);
		dep->de_Attributes |= ATTR_ARCHIVE;
	}
	if ((dep->de_pmp->pm_flags & MSDOSFSMNT_NOWIN95) == 0) {
		if (dep->de_flag & DE_ACCESS)  {
			if (acc == NULL)
				acc = ts == NULL ?
				    (getnanotime(&tsb), ts = &tsb) : ts;
			msdosfs_unix2dostime(acc, gmtoff, &dep->de_ADate,
			    NULL, NULL);
		}
		if (dep->de_flag & DE_CREATE) {
			if (cre == NULL)
				cre = ts == NULL ?
				    (getnanotime(&tsb), ts = &tsb) : ts;
			msdosfs_unix2dostime(cre, gmtoff, &dep->de_CDate,
			    &dep->de_CTime, &dep->de_CHun);
		}
	}

	dep->de_flag &= ~(DE_UPDATE | DE_CREATE | DE_ACCESS);
}

/* Global vfs data structures for msdosfs */
int (**msdosfs_vnodeop_p)(void *);
const struct vnodeopv_entry_desc msdosfs_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_parsepath_desc, genfs_parsepath },	/* parsepath */
	{ &vop_lookup_desc, msdosfs_lookup },		/* lookup */
	{ &vop_create_desc, msdosfs_create },		/* create */
	{ &vop_mknod_desc, genfs_eopnotsupp },		/* mknod */
	{ &vop_open_desc, genfs_nullop },		/* open */
	{ &vop_close_desc, msdosfs_close },		/* close */
	{ &vop_access_desc, msdosfs_access },		/* access */
	{ &vop_accessx_desc, genfs_accessx },		/* accessx */
	{ &vop_getattr_desc, msdosfs_getattr },		/* getattr */
	{ &vop_setattr_desc, msdosfs_setattr },		/* setattr */
	{ &vop_read_desc, msdosfs_read },		/* read */
	{ &vop_write_desc, msdosfs_write },		/* write */
	{ &vop_fallocate_desc, genfs_eopnotsupp },	/* fallocate */
	{ &vop_fdiscard_desc, genfs_eopnotsupp },	/* fdiscard */
	{ &vop_fcntl_desc, genfs_fcntl },		/* fcntl */
	{ &vop_ioctl_desc, genfs_enoioctl },		/* ioctl */
	{ &vop_poll_desc, genfs_poll },			/* poll */
	{ &vop_kqfilter_desc, genfs_kqfilter },		/* kqfilter */
	{ &vop_revoke_desc, genfs_revoke },		/* revoke */
	{ &vop_mmap_desc, genfs_mmap },			/* mmap */
	{ &vop_fsync_desc, msdosfs_fsync },		/* fsync */
	{ &vop_seek_desc, genfs_seek },			/* seek */
	{ &vop_remove_desc, msdosfs_remove },		/* remove */
	{ &vop_link_desc, genfs_eopnotsupp },		/* link */
	{ &vop_rename_desc, msdosfs_rename },		/* rename */
	{ &vop_mkdir_desc, msdosfs_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, msdosfs_rmdir },		/* rmdir */
	{ &vop_symlink_desc, genfs_eopnotsupp },	/* symlink */
	{ &vop_readdir_desc, msdosfs_readdir },		/* readdir */
	{ &vop_readlink_desc, genfs_einval },		/* readlink */
	{ &vop_abortop_desc, genfs_abortop },		/* abortop */
	{ &vop_inactive_desc, msdosfs_inactive },	/* inactive */
	{ &vop_reclaim_desc, msdosfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, genfs_lock },			/* lock */
	{ &vop_unlock_desc, genfs_unlock },		/* unlock */
	{ &vop_bmap_desc, msdosfs_bmap },		/* bmap */
	{ &vop_strategy_desc, msdosfs_strategy },	/* strategy */
	{ &vop_print_desc, msdosfs_print },		/* print */
	{ &vop_islocked_desc, genfs_islocked },		/* islocked */
	{ &vop_pathconf_desc, msdosfs_pathconf },	/* pathconf */
	{ &vop_advlock_desc, msdosfs_advlock },		/* advlock */
	{ &vop_bwrite_desc, vn_bwrite },		/* bwrite */
	{ &vop_getpages_desc, genfs_getpages },		/* getpages */
	{ &vop_putpages_desc, genfs_putpages },		/* putpages */
	{ NULL, NULL }
};
const struct vnodeopv_desc msdosfs_vnodeop_opv_desc =
	{ &msdosfs_vnodeop_p, msdosfs_vnodeop_entries };
