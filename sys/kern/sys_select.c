/*	$NetBSD: sys_select.c,v 1.68 2024/11/26 23:10:15 khorben Exp $	*/

/*-
 * Copyright (c) 2007, 2008, 2009, 2010, 2019, 2020, 2023
 *     The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran and Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)sys_generic.c	8.9 (Berkeley) 2/14/95
 */

/*
 * System calls of synchronous I/O multiplexing subsystem.
 *
 * Locking
 *
 * Two locks are used: <object-lock> and selcluster_t::sc_lock.
 *
 * The <object-lock> might be a device driver or another subsystem, e.g.
 * socket or pipe.  This lock is not exported, and thus invisible to this
 * subsystem.  Mainly, synchronisation between selrecord() and selnotify()
 * routines depends on this lock, as it will be described in the comments.
 *
 * Lock order
 *
 *	<object-lock> ->
 *		selcluster_t::sc_lock
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sys_select.c,v 1.68 2024/11/26 23:10:15 khorben Exp $");

#include <sys/param.h>

#include <sys/atomic.h>
#include <sys/bitops.h>
#include <sys/cpu.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lwp.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/sleepq.h>
#include <sys/socketvar.h>
#include <sys/socketvar.h>
#include <sys/syncobj.h>
#include <sys/syscallargs.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/uio.h>

/* Flags for lwp::l_selflag. */
#define	SEL_RESET	0	/* awoken, interrupted, or not yet polling */
#define	SEL_SCANNING	1	/* polling descriptors */
#define	SEL_BLOCKING	2	/* blocking and waiting for event */
#define	SEL_EVENT	3	/* interrupted, events set directly */

/*
 * Per-cluster state for select()/poll().  For a system with fewer
 * than 64 CPUs, this gives us per-CPU clusters.
 */
#define	SELCLUSTERS	64
#define	SELCLUSTERMASK	(SELCLUSTERS - 1)

typedef struct selcluster {
	kmutex_t	*sc_lock;
	sleepq_t	sc_sleepq;
	uint64_t	sc_mask;
	int		sc_ncoll;
} selcluster_t;

static inline int	selscan(char *, const int, const size_t, register_t *);
static inline int	pollscan(struct pollfd *, const int, register_t *);
static void		selclear(void);

static const int sel_flag[] = {
	POLLRDNORM | POLLHUP | POLLERR,
	POLLWRNORM | POLLHUP | POLLERR,
	POLLRDBAND
};

/* 
 * LWPs are woken using the sleep queue only due to a collision, the case
 * with the maximum Suck Factor.  Save the cost of sorting for named waiters
 * by inserting in LIFO order.  In the future it would be preferable to not
 * enqueue LWPs at all, unless subject to a collision.
 */
syncobj_t select_sobj = {
	.sobj_name	= "select",
	.sobj_flag	= SOBJ_SLEEPQ_LIFO,
	.sobj_boostpri  = PRI_KERNEL,
	.sobj_unsleep	= sleepq_unsleep,
	.sobj_changepri	= sleepq_changepri,
	.sobj_lendpri	= sleepq_lendpri,
	.sobj_owner	= syncobj_noowner,
};

static selcluster_t	*selcluster[SELCLUSTERS] __read_mostly;
static int		direct_select __read_mostly = 0;

/* Operations: either select() or poll(). */
const char		selop_select[] = "select";
const char		selop_poll[] = "poll";

/*
 * Select system call.
 */
int
sys___pselect50(struct lwp *l, const struct sys___pselect50_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int)				nd;
		syscallarg(fd_set *)			in;
		syscallarg(fd_set *)			ou;
		syscallarg(fd_set *)			ex;
		syscallarg(const struct timespec *)	ts;
		syscallarg(sigset_t *)			mask;
	} */
	struct timespec	ats, *ts = NULL;
	sigset_t	amask, *mask = NULL;
	int		error;

	if (SCARG(uap, ts)) {
		error = copyin(SCARG(uap, ts), &ats, sizeof(ats));
		if (error)
			return error;
		ts = &ats;
	}
	if (SCARG(uap, mask) != NULL) {
		error = copyin(SCARG(uap, mask), &amask, sizeof(amask));
		if (error)
			return error;
		mask = &amask;
	}

	return selcommon(retval, SCARG(uap, nd), SCARG(uap, in),
	    SCARG(uap, ou), SCARG(uap, ex), ts, mask);
}

int
sys___select50(struct lwp *l, const struct sys___select50_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int)			nd;
		syscallarg(fd_set *)		in;
		syscallarg(fd_set *)		ou;
		syscallarg(fd_set *)		ex;
		syscallarg(struct timeval *)	tv;
	} */
	struct timeval atv;
	struct timespec ats, *ts = NULL;
	int error;

	if (SCARG(uap, tv)) {
		error = copyin(SCARG(uap, tv), (void *)&atv, sizeof(atv));
		if (error)
			return error;

		if (atv.tv_usec < 0 || atv.tv_usec >= 1000000)
			return EINVAL;

		TIMEVAL_TO_TIMESPEC(&atv, &ats);
		ts = &ats;
	}

	return selcommon(retval, SCARG(uap, nd), SCARG(uap, in),
	    SCARG(uap, ou), SCARG(uap, ex), ts, NULL);
}

/*
 * sel_do_scan: common code to perform the scan on descriptors.
 */
static int
sel_do_scan(const char *opname, void *fds, const int nf, const size_t ni,
    struct timespec *ts, sigset_t *mask, register_t *retval)
{
	lwp_t		* const l = curlwp;
	selcluster_t	*sc;
	kmutex_t	*lock;
	struct timespec	sleepts;
	int		error, timo;

	timo = 0;
	if (ts && inittimeleft(ts, &sleepts) == -1) {
		return EINVAL;
	}

	if (__predict_false(mask))
		sigsuspendsetup(l, mask);

	/*
	 * We may context switch during or at any time after picking a CPU
	 * and cluster to associate with, but it doesn't matter.  In the
	 * unlikely event we migrate elsewhere all we risk is a little lock
	 * contention; correctness is not sacrificed.
	 */
	sc = curcpu()->ci_data.cpu_selcluster;
	lock = sc->sc_lock;
	l->l_selcluster = sc;

	if (opname == selop_select) {
		l->l_selbits = fds;
		l->l_selni = ni;
	} else {
		l->l_selbits = NULL;
	}

	for (;;) {
		int ncoll;

		SLIST_INIT(&l->l_selwait);
		l->l_selret = 0;

		/*
		 * No need to lock.  If this is overwritten by another value
		 * while scanning, we will retry below.  We only need to see
		 * exact state from the descriptors that we are about to poll,
		 * and lock activity resulting from fo_poll is enough to
		 * provide an up to date value for new polling activity.
		 */
		if (ts && (ts->tv_sec | ts->tv_nsec | direct_select) == 0) {
			/* Non-blocking: no need for selrecord()/selclear() */
			l->l_selflag = SEL_RESET;
		} else {
			l->l_selflag = SEL_SCANNING;
		}
		ncoll = sc->sc_ncoll;
		membar_release();

		if (opname == selop_select) {
			error = selscan((char *)fds, nf, ni, retval);
		} else {
			error = pollscan((struct pollfd *)fds, nf, retval);
		}
		if (error || *retval)
			break;
		if (ts && (timo = gettimeleft(ts, &sleepts)) <= 0)
			break;
		/*
		 * Acquire the lock and perform the (re)checks.  Note, if
		 * collision has occurred, then our state does not matter,
		 * as we must perform re-scan.  Therefore, check it first.
		 */
state_check:
		mutex_spin_enter(lock);
		if (__predict_false(sc->sc_ncoll != ncoll)) {
			/* Collision: perform re-scan. */
			mutex_spin_exit(lock);
			selclear();
			continue;
		}
		if (__predict_true(l->l_selflag == SEL_EVENT)) {
			/* Events occurred, they are set directly. */
			mutex_spin_exit(lock);
			break;
		}
		if (__predict_true(l->l_selflag == SEL_RESET)) {
			/* Events occurred, but re-scan is requested. */
			mutex_spin_exit(lock);
			selclear();
			continue;
		}
		/* Nothing happen, therefore - sleep. */
		l->l_selflag = SEL_BLOCKING;
		KASSERT(l->l_blcnt == 0);
		(void)sleepq_enter(&sc->sc_sleepq, l, lock);
		sleepq_enqueue(&sc->sc_sleepq, sc, opname, &select_sobj, true);
		error = sleepq_block(timo, true, &select_sobj, 0);
		if (error != 0) {
			break;
		}
		/* Awoken: need to check the state. */
		goto state_check;
	}
	selclear();

	/* Add direct events if any. */
	if (l->l_selflag == SEL_EVENT) {
		KASSERT(l->l_selret != 0);
		*retval += l->l_selret;
	}

	if (__predict_false(mask))
		sigsuspendteardown(l);

	/* select and poll are not restarted after signals... */
	if (error == ERESTART)
		return EINTR;
	if (error == EWOULDBLOCK)
		return 0;
	return error;
}

/* designed to be compatible with FD_SET() FD_ISSET() ... */
static int
anyset(void *p, size_t nbits)
{
	size_t nwords;
	__fd_mask mask;
	__fd_mask *f = (__fd_mask *)p;

	nwords = nbits / __NFDBITS;

	while (nwords-- > 0)
		if (*f++ != 0)
			return 1;

	nbits &= __NFDMASK;
	if (nbits != 0) {
		mask = (1U << nbits) - 1;
		if ((*f & mask) != 0)
			return 1;
	}
	return 0;
}

int
selcommon(register_t *retval, int nd, fd_set *u_in, fd_set *u_ou,
    fd_set *u_ex, struct timespec *ts, sigset_t *mask)
{
	char		smallbits[howmany(FD_SETSIZE, NFDBITS) *
			    sizeof(fd_mask) * 6];
	char 		*bits;
	int		error, nf, fb, db;
	size_t		ni;

	if (nd < 0)
		return EINVAL;

	nf = atomic_load_consume(&curlwp->l_fd->fd_dt)->dt_nfiles;

	/*
	 * Don't allow absurdly large numbers of fds to be selected.
	 * (used to silently truncate, naughty naughty, no more ...)
	 *
	 * The additional FD_SETSIZE allows for cases where the limit
	 * is not a round binary number, but the fd_set wants to
	 * include all the possible fds, as fd_sets are always
	 * multiples of 32 bits (__NFDBITS extra would be enough).
	 *
	 * The first test handles the case where the res limit has been
	 * set lower after some fds were opened, we always allow selecting
	 * up to the highest currently open fd.
	 */
	if (nd > nf + FD_SETSIZE &&
	    nd > curlwp->l_proc->p_rlimit[RLIMIT_NOFILE].rlim_max + FD_SETSIZE)
		return EINVAL;

	fb = howmany(nf, __NFDBITS);		/* how many fd_masks */
	db = howmany(nd, __NFDBITS);

	if (db > fb) {
		size_t off;

		/*
		 * the application wants to supply more fd masks than can
		 * possibly represent valid file descriptors.
		 *
		 * Check the excess fd_masks, if any bits are set in them
		 * that must be an error (cannot represent valid fd).
		 *
		 * Supplying lots of extra cleared fd_masks is dumb,
		 * but harmless, so allow that.
		 */
		ni = (db - fb) * sizeof(fd_mask);	/* excess bytes */
		bits = smallbits;

		/* skip over the valid fd_masks, those will be checked below */
		off = howmany(nf, __NFDBITS) * sizeof(__fd_mask);

		nd -= fb * NFDBITS;	/* the number of excess fds */

#define checkbits(name, o, sz, fds)					\
		do {							\
		    if (u_ ## name != NULL) {				\
			error = copyin((char *)u_ ## name + o,		\
					bits, sz);			\
			if (error)					\
			    goto fail;					\
			if (anyset(bits, (fds) ?			\
				 (size_t)(fds) : CHAR_BIT * (sz))) {	\
			    error = EBADF;				\
			    goto fail;					\
			}						\
		    }							\
		} while (0)

		while (ni > sizeof(smallbits)) {
			checkbits(in, off, sizeof(smallbits), 0);
			checkbits(ou, off, sizeof(smallbits), 0);
			checkbits(ex, off, sizeof(smallbits), 0);

			off += sizeof(smallbits);
			ni -= sizeof(smallbits);
			nd -= sizeof(smallbits) * CHAR_BIT;
		}
		checkbits(in, off, ni, nd);
		checkbits(ou, off, ni, nd);
		checkbits(ex, off, ni, nd);
#undef checkbits

		db = fb;	/* now just check the plausible fds */
		nd = db * __NFDBITS;
	}

	ni = db * sizeof(fd_mask);
	if (ni * 6 > sizeof(smallbits))
		bits = kmem_alloc(ni * 6, KM_SLEEP);
	else
		bits = smallbits;

#define	getbits(name, x)						\
	do {								\
		if (u_ ## name) {					\
			error = copyin(u_ ## name, bits + ni * x, ni);	\
			if (error)					\
				goto fail;				\
		} else							\
			memset(bits + ni * x, 0, ni);			\
	} while (0)

	getbits(in, 0);
	getbits(ou, 1);
	getbits(ex, 2);
#undef	getbits

	error = sel_do_scan(selop_select, bits, nd, ni, ts, mask, retval);

#define copyback(name, x)						\
		do {							\
			if (error == 0 && u_ ## name != NULL)		\
				error = copyout(bits + ni * x,		\
						u_ ## name, ni);	\
		} while (0)

	copyback(in, 3);
	copyback(ou, 4);
	copyback(ex, 5);
#undef copyback

 fail:
	if (bits != smallbits)
		kmem_free(bits, ni * 6);
	return (error);
}

static inline int
selscan(char *bits, const int nfd, const size_t ni, register_t *retval)
{
	fd_mask *ibitp, *obitp;
	int msk, i, j, fd, n;
	file_t *fp;
	lwp_t *l;

	ibitp = (fd_mask *)(bits + ni * 0);
	obitp = (fd_mask *)(bits + ni * 3);
	n = 0;
	l = curlwp;

	memset(obitp, 0, ni * 3);
	for (msk = 0; msk < 3; msk++) {
		for (i = 0; i < nfd; i += NFDBITS) {
			fd_mask ibits, obits;

			ibits = *ibitp;
			obits = 0;
			while ((j = ffs(ibits)) && (fd = i + --j) < nfd) {
				ibits &= ~(1U << j);
				if ((fp = fd_getfile(fd)) == NULL)
					return (EBADF);
				/*
				 * Setup an argument to selrecord(), which is
				 * a file descriptor number.
				 */
				l->l_selrec = fd;
				if ((*fp->f_ops->fo_poll)(fp, sel_flag[msk])) {
					if (!direct_select) {
						/*
						 * Have events: do nothing in
						 * selrecord().
						 */
						l->l_selflag = SEL_RESET;
					}
					obits |= (1U << j);
					n++;
				}
				fd_putfile(fd);
			}
			if (obits != 0) {
				if (direct_select) {
					kmutex_t *lock;
					lock = l->l_selcluster->sc_lock;
					mutex_spin_enter(lock);
					*obitp |= obits;
					mutex_spin_exit(lock);
				} else {
					*obitp |= obits;
				}
			}
			ibitp++;
			obitp++;
		}
	}
	*retval = n;
	return (0);
}

/*
 * Poll system call.
 */
int
sys_poll(struct lwp *l, const struct sys_poll_args *uap, register_t *retval)
{
	/* {
		syscallarg(struct pollfd *)	fds;
		syscallarg(u_int)		nfds;
		syscallarg(int)			timeout;
	} */
	struct timespec	ats, *ts = NULL;

	if (SCARG(uap, timeout) != INFTIM) {
		ats.tv_sec = SCARG(uap, timeout) / 1000;
		ats.tv_nsec = (SCARG(uap, timeout) % 1000) * 1000000;
		ts = &ats;
	}

	return pollcommon(retval, SCARG(uap, fds), SCARG(uap, nfds), ts, NULL);
}

/*
 * Poll system call.
 */
int
sys___pollts50(struct lwp *l, const struct sys___pollts50_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(struct pollfd *)		fds;
		syscallarg(u_int)			nfds;
		syscallarg(const struct timespec *)	ts;
		syscallarg(const sigset_t *)		mask;
	} */
	struct timespec	ats, *ts = NULL;
	sigset_t	amask, *mask = NULL;
	int		error;

	if (SCARG(uap, ts)) {
		error = copyin(SCARG(uap, ts), &ats, sizeof(ats));
		if (error)
			return error;
		ts = &ats;
	}
	if (SCARG(uap, mask)) {
		error = copyin(SCARG(uap, mask), &amask, sizeof(amask));
		if (error)
			return error;
		mask = &amask;
	}

	return pollcommon(retval, SCARG(uap, fds), SCARG(uap, nfds), ts, mask);
}

int
pollcommon(register_t *retval, struct pollfd *u_fds, u_int nfds,
    struct timespec *ts, sigset_t *mask)
{
	struct pollfd	smallfds[32];
	struct pollfd	*fds;
	int		error;
	size_t		ni;

	if (nfds > curlwp->l_proc->p_rlimit[RLIMIT_NOFILE].rlim_max + 1000) {
		/*
		 * Prevent userland from causing over-allocation.
		 * Raising the default limit too high can still cause
		 * a lot of memory to be allocated, but this also means
		 * that the file descriptor array will also be large.
		 *
		 * To reduce the memory requirements here, we could 
		 * process the 'fds' array in chunks, but that
		 * is a lot of code that isn't normally useful.
		 * (Or just move the copyin/out into pollscan().)
		 *
		 * Historically the code silently truncated 'fds' to
		 * dt_nfiles entries - but that does cause issues.
		 *
		 * Using the max limit equivalent to sysctl
		 * kern.maxfiles is the moral equivalent of OPEN_MAX
		 * as specified by POSIX.
		 *
		 * We add a slop of 1000 in case the resource limit was
		 * changed after opening descriptors or the same descriptor
		 * was specified more than once.
		 */
		return EINVAL;
	}
	ni = nfds * sizeof(struct pollfd);
	if (ni > sizeof(smallfds))
		fds = kmem_alloc(ni, KM_SLEEP);
	else
		fds = smallfds;

	error = copyin(u_fds, fds, ni);
	if (error)
		goto fail;

	error = sel_do_scan(selop_poll, fds, nfds, ni, ts, mask, retval);
	if (error == 0)
		error = copyout(fds, u_fds, ni);
 fail:
	if (fds != smallfds)
		kmem_free(fds, ni);
	return (error);
}

static inline int
pollscan(struct pollfd *fds, const int nfd, register_t *retval)
{
	file_t *fp;
	int i, n = 0, revents;

	for (i = 0; i < nfd; i++, fds++) {
		fds->revents = 0;
		if (fds->fd < 0) {
			revents = 0;
		} else if ((fp = fd_getfile(fds->fd)) == NULL) {
			revents = POLLNVAL;
		} else {
			/*
			 * Perform poll: registers select request or returns
			 * the events which are set.  Setup an argument for
			 * selrecord(), which is a pointer to struct pollfd.
			 */
			curlwp->l_selrec = (uintptr_t)fds;
			revents = (*fp->f_ops->fo_poll)(fp,
			    fds->events | POLLERR | POLLHUP);
			fd_putfile(fds->fd);
		}
		if (revents) {
			if (!direct_select)  {
				/* Have events: do nothing in selrecord(). */
				curlwp->l_selflag = SEL_RESET;
			}
			fds->revents = revents;
			n++;
		}
	}
	*retval = n;
	return (0);
}

int
seltrue(dev_t dev, int events, lwp_t *l)
{

	return (events & (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM));
}

/*
 * Record a select request.  Concurrency issues:
 *
 * The caller holds the same lock across calls to selrecord() and
 * selnotify(), so we don't need to consider a concurrent wakeup
 * while in this routine.
 *
 * The only activity we need to guard against is selclear(), called by
 * another thread that is exiting sel_do_scan().
 * `sel_lwp' can only become non-NULL while the caller's lock is held,
 * so it cannot become non-NULL due to a change made by another thread
 * while we are in this routine.  It can only become _NULL_ due to a
 * call to selclear().
 *
 * If it is non-NULL and != selector there is the potential for
 * selclear() to be called by another thread.  If either of those
 * conditions are true, we're not interested in touching the `named
 * waiter' part of the selinfo record because we need to record a
 * collision.  Hence there is no need for additional locking in this
 * routine.
 */
void
selrecord(lwp_t *selector, struct selinfo *sip)
{
	selcluster_t *sc;
	lwp_t *other;

	KASSERT(selector == curlwp);

	sc = selector->l_selcluster;
	other = sip->sel_lwp;

	if (selector->l_selflag == SEL_RESET) {
		/* 0. We're not going to block - will poll again if needed. */
	} else if (other == selector) {
		/* 1. We (selector) already claimed to be the first LWP. */
		KASSERT(sip->sel_cluster == sc);
	} else if (other == NULL) {
		/*
		 * 2. No first LWP, therefore we (selector) are the first.
		 *
		 * There may be unnamed waiters (collisions).  Issue a memory
		 * barrier to ensure that we access sel_lwp (above) before
		 * other fields - this guards against a call to selclear().
		 */
		membar_acquire();
		sip->sel_lwp = selector;
		SLIST_INSERT_HEAD(&selector->l_selwait, sip, sel_chain);
		/* Copy the argument, which is for selnotify(). */
		sip->sel_fdinfo = selector->l_selrec;
		/* Replace selinfo's lock with the chosen cluster's lock. */
		sip->sel_cluster = sc;
	} else {
		/* 3. Multiple waiters: record a collision. */
		sip->sel_collision |= sc->sc_mask;
		KASSERT(sip->sel_cluster != NULL);
	}
}

/*
 * Record a knote.
 *
 * The caller holds the same lock as for selrecord().
 */
void
selrecord_knote(struct selinfo *sip, struct knote *kn)
{
	klist_insert(&sip->sel_klist, kn);
}

/*
 * Remove a knote.
 *
 * The caller holds the same lock as for selrecord().
 *
 * Returns true if the last knote was removed and the list
 * is now empty.
 */
bool
selremove_knote(struct selinfo *sip, struct knote *kn)
{
	return klist_remove(&sip->sel_klist, kn);
}

/*
 * sel_setevents: a helper function for selnotify(), to set the events
 * for LWP sleeping in selcommon() or pollcommon().
 */
static inline bool
sel_setevents(lwp_t *l, struct selinfo *sip, const int events)
{
	const int oflag = l->l_selflag;
	int ret = 0;

	/*
	 * If we require re-scan or it was required by somebody else,
	 * then just (re)set SEL_RESET and return.
	 */
	if (__predict_false(events == 0 || oflag == SEL_RESET)) {
		l->l_selflag = SEL_RESET;
		return true;
	}
	/*
	 * Direct set.  Note: select state of LWP is locked.  First,
	 * determine whether it is selcommon() or pollcommon().
	 */
	if (l->l_selbits != NULL) {
		const size_t ni = l->l_selni;
		fd_mask *fds = (fd_mask *)l->l_selbits;
		fd_mask *ofds = (fd_mask *)((char *)fds + ni * 3);
		const int fd = sip->sel_fdinfo, fbit = 1 << (fd & __NFDMASK);
		const int idx = fd >> __NFDSHIFT;
		int n;

		for (n = 0; n < 3; n++) {
			if ((fds[idx] & fbit) != 0 &&
			    (ofds[idx] & fbit) == 0 &&
			    (sel_flag[n] & events)) {
				ofds[idx] |= fbit;
				ret++;
			}
			fds = (fd_mask *)((char *)fds + ni);
			ofds = (fd_mask *)((char *)ofds + ni);
		}
	} else {
		struct pollfd *pfd = (void *)sip->sel_fdinfo;
		int revents = events & (pfd->events | POLLERR | POLLHUP);

		if (revents) {
			if (pfd->revents == 0)
				ret = 1;
			pfd->revents |= revents;
		}
	}
	/* Check whether there are any events to return. */
	if (!ret) {
		return false;
	}
	/* Indicate direct set and note the event (cluster lock is held). */
	l->l_selflag = SEL_EVENT;
	l->l_selret += ret;
	return true;
}

/*
 * Do a wakeup when a selectable event occurs.  Concurrency issues:
 *
 * As per selrecord(), the caller's object lock is held.  If there
 * is a named waiter, we must acquire the associated selcluster's lock
 * in order to synchronize with selclear() and pollers going to sleep
 * in sel_do_scan().
 *
 * sip->sel_cluser cannot change at this point, as it is only changed
 * in selrecord(), and concurrent calls to selrecord() are locked
 * out by the caller.
 */
void
selnotify(struct selinfo *sip, int events, long knhint)
{
	selcluster_t *sc;
	uint64_t mask;
	int index, oflag;
	lwp_t *l;
	kmutex_t *lock;

	KNOTE(&sip->sel_klist, knhint);

	if (sip->sel_lwp != NULL) {
		/* One named LWP is waiting. */
		sc = sip->sel_cluster;
		lock = sc->sc_lock;
		mutex_spin_enter(lock);
		/* Still there? */
		if (sip->sel_lwp != NULL) {
			/*
			 * Set the events for our LWP and indicate that.
			 * Otherwise, request for a full re-scan.
			 */
			l = sip->sel_lwp;
			oflag = l->l_selflag;

			if (!direct_select) {
				l->l_selflag = SEL_RESET;
			} else if (!sel_setevents(l, sip, events)) {
				/* No events to return. */
				mutex_spin_exit(lock);
				return;
			}

			/*
			 * If thread is sleeping, wake it up.  If it's not
			 * yet asleep, it will notice the change in state
			 * and will re-poll the descriptors.
			 */
			if (oflag == SEL_BLOCKING && l->l_mutex == lock) {
				KASSERT(l->l_wchan == sc);
				sleepq_remove(l->l_sleepq, l, true);
			}
		}
		mutex_spin_exit(lock);
	}

	if ((mask = sip->sel_collision) != 0) {
		/*
		 * There was a collision (multiple waiters): we must
		 * inform all potentially interested waiters.
		 */
		sip->sel_collision = 0;
		do {
			index = ffs64(mask) - 1;
			mask ^= __BIT(index);
			sc = selcluster[index];
			lock = sc->sc_lock;
			mutex_spin_enter(lock);
			sc->sc_ncoll++;
			sleepq_wake(&sc->sc_sleepq, sc, (u_int)-1, lock);
		} while (__predict_false(mask != 0));
	}
}

/*
 * Remove an LWP from all objects that it is waiting for.  Concurrency
 * issues:
 *
 * The object owner's (e.g. device driver) lock is not held here.  Calls
 * can be made to selrecord() and we do not synchronize against those
 * directly using locks.  However, we use `sel_lwp' to lock out changes.
 * Before clearing it we must use memory barriers to ensure that we can
 * safely traverse the list of selinfo records.
 */
static void
selclear(void)
{
	struct selinfo *sip, *next;
	selcluster_t *sc;
	lwp_t *l;
	kmutex_t *lock;

	l = curlwp;
	sc = l->l_selcluster;
	lock = sc->sc_lock;

	/*
	 * If the request was non-blocking, or we found events on the first
	 * descriptor, there will be no need to clear anything - avoid
	 * taking the lock.
	 */
	if (SLIST_EMPTY(&l->l_selwait)) {
		return;
	}

	mutex_spin_enter(lock);
	for (sip = SLIST_FIRST(&l->l_selwait); sip != NULL; sip = next) {
		KASSERT(sip->sel_lwp == l);
		KASSERT(sip->sel_cluster == l->l_selcluster);

		/*
		 * Read link to next selinfo record, if any.
		 * It's no longer safe to touch `sip' after clearing
		 * `sel_lwp', so ensure that the read of `sel_chain'
		 * completes before the clearing of sel_lwp becomes
		 * globally visible.
		 */
		next = SLIST_NEXT(sip, sel_chain);
		/* Release the record for another named waiter to use. */
		atomic_store_release(&sip->sel_lwp, NULL);
	}
	mutex_spin_exit(lock);
}

/*
 * Initialize the select/poll system calls.  Called once for each
 * CPU in the system, as they are attached.
 */
void
selsysinit(struct cpu_info *ci)
{
	selcluster_t *sc;
	u_int index;

	/* If already a cluster in place for this bit, re-use. */
	index = cpu_index(ci) & SELCLUSTERMASK;
	sc = selcluster[index];
	if (sc == NULL) {
		sc = kmem_alloc(roundup2(sizeof(selcluster_t),
		    coherency_unit) + coherency_unit, KM_SLEEP);
		sc = (void *)roundup2((uintptr_t)sc, coherency_unit);
		sc->sc_lock = mutex_obj_alloc(MUTEX_DEFAULT, IPL_SCHED);
		sleepq_init(&sc->sc_sleepq);
		sc->sc_ncoll = 0;
		sc->sc_mask = __BIT(index);
		selcluster[index] = sc;
	}
	ci->ci_data.cpu_selcluster = sc;
}

/*
 * Initialize a selinfo record.
 */
void
selinit(struct selinfo *sip)
{

	memset(sip, 0, sizeof(*sip));
	klist_init(&sip->sel_klist);
}

/*
 * Destroy a selinfo record.  The owning object must not gain new
 * references while this is in progress: all activity on the record
 * must be stopped.
 *
 * Concurrency issues: we only need guard against a call to selclear()
 * by a thread exiting sel_do_scan().  The caller has prevented further
 * references being made to the selinfo record via selrecord(), and it
 * will not call selnotify() again.
 */
void
seldestroy(struct selinfo *sip)
{
	selcluster_t *sc;
	kmutex_t *lock;
	lwp_t *l;

	klist_fini(&sip->sel_klist);

	if (sip->sel_lwp == NULL)
		return;

	/*
	 * Lock out selclear().  The selcluster pointer can't change while
	 * we are here since it is only ever changed in selrecord(),
	 * and that will not be entered again for this record because
	 * it is dying.
	 */
	KASSERT(sip->sel_cluster != NULL);
	sc = sip->sel_cluster;
	lock = sc->sc_lock;
	mutex_spin_enter(lock);
	if ((l = sip->sel_lwp) != NULL) {
		/*
		 * This should rarely happen, so although SLIST_REMOVE()
		 * is slow, using it here is not a problem.
		 */
		KASSERT(l->l_selcluster == sc);
		SLIST_REMOVE(&l->l_selwait, sip, selinfo, sel_chain);
		sip->sel_lwp = NULL;
	}
	mutex_spin_exit(lock);
}

/*
 * System control nodes.
 */
SYSCTL_SETUP(sysctl_select_setup, "sysctl select setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
		CTLTYPE_INT, "direct_select",
		SYSCTL_DESCR("Enable/disable direct select (for testing)"),
		NULL, 0, &direct_select, 0,
		CTL_KERN, CTL_CREATE, CTL_EOL);
}
