/*	$NetBSD: pthread_int.h,v 1.114 2025/04/02 14:23:34 riastradh Exp $	*/

/*-
 * Copyright (c) 2001, 2002, 2003, 2006, 2007, 2008, 2020
 *     The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Nathan J. Williams and Andrew Doran.
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

#ifndef _LIB_PTHREAD_INT_H
#define _LIB_PTHREAD_INT_H

#include <sys/tls.h>

/* #define PTHREAD__DEBUG */

#include "pthread_types.h"
#include "pthread_queue.h"
#include "pthread_md.h"

#include <sys/atomic.h>
#include <sys/rbtree.h>
#include <sys/param.h>

#include <limits.h>
#include <lwp.h>
#include <signal.h>
#include <stdbool.h>

#include <machine/lwp_private.h>

#ifdef __GNUC__
#define	PTHREAD_HIDE	__attribute__ ((visibility("hidden")))
#else
#define	PTHREAD_HIDE	/* nothing */
#endif

#define	PTHREAD__UNPARK_MAX	128

/*
 * The size of this structure needs to be no larger than struct
 * __pthread_cleanup_store, defined in pthread.h.
 */
struct pt_clean_t {
	PTQ_ENTRY(pt_clean_t)	ptc_next;
	void	(*ptc_cleanup)(void *);
	void	*ptc_arg;
};

/* Private data for pthread_attr_t */
struct pthread_attr_private {
	char ptap_name[PTHREAD_MAX_NAMELEN_NP];
	void *ptap_namearg;
	void *ptap_stackaddr;
	size_t ptap_stacksize;
	size_t ptap_guardsize;
	struct sched_param ptap_sp;
	int ptap_policy;
};

struct pthread_lock_ops {
	void	(*plo_init)(__cpu_simple_lock_t *);
	int	(*plo_try)(__cpu_simple_lock_t *);
	void	(*plo_unlock)(__cpu_simple_lock_t *);
	void	(*plo_lock)(__cpu_simple_lock_t *);
};

struct	__pthread_st {
	pthread_t	pt_self;	/* Must be first. */
#if defined(__HAVE_TLS_VARIANT_I) || defined(__HAVE_TLS_VARIANT_II)
	struct tls_tcb	*pt_tls;	/* Thread Local Storage area */
#endif
	unsigned int	pt_magic;	/* Magic number */
	int		pt_state;	/* running, blocked, etc. */
	int		pt_flags;	/* see PT_FLAG_* below */
	_Atomic unsigned int	pt_cancel;	/* Cancellation */
	int		pt_errno;	/* Thread-specific errno. */
	stack_t		pt_stack;	/* Our stack */
	bool		pt_stack_allocated;
	size_t		pt_guardsize;
	void		*pt_exitval;	/* Read by pthread_join() */
	char		*pt_name;	/* Thread's name, set by the app. */
	struct pthread_lock_ops pt_lockops;/* Cached to avoid PIC overhead */
	void		*(*pt_func)(void *);/* Function to call at start. */
	void		*pt_arg;	/* Argument to pass at start. */

	/* Stack of cancellation cleanup handlers and their arguments */
	PTQ_HEAD(, pt_clean_t)	pt_cleanup_stack;

	/* LWP ID and entry on the list of all threads. */
	lwpid_t		pt_lid;
	PTQ_ENTRY(__pthread_st)	pt_deadq;

	/*
	 * rbtree node and entry on the list of all threads.  pt_alltree in
	 * its own cacheline, so pthread__find() is not needlessly impacted
	 * by threads going about their normal business.  pt_allq is
	 * adjusted at the same time as pt_alltree.
	 */
	rb_node_t	pt_alltree __aligned(COHERENCY_UNIT);
	PTQ_ENTRY(__pthread_st) pt_allq;

	/* Lock on state also gets its own line. */
	pthread_mutex_t	pt_lock __aligned(COHERENCY_UNIT);

	/*
	 * General synchronization data.  We try to align, as threads
	 * on other CPUs will access this data frequently.
	 */
	int		pt_dummy1 __aligned(COHERENCY_UNIT);
	struct lwpctl 	*pt_lwpctl;	/* Kernel/user comms area */
	volatile int	pt_rwlocked;	/* Handed rwlock successfully */
	void * volatile	pt_sleepobj;	/* Object slept on */
	PTQ_ENTRY(__pthread_st) pt_sleep;

	/* Thread-specific data.  Large so it sits close to the end. */
	int		pt_havespecific __aligned(COHERENCY_UNIT);
	struct pt_specific {
		void *pts_value;
		PTQ_ENTRY(pt_specific) pts_next;
	} pt_specific[];
};

/* Thread states */
#define PT_STATE_RUNNING	1
#define PT_STATE_ZOMBIE		5
#define PT_STATE_DEAD		6

/* Flag values */

#define PT_FLAG_DETACHED	0x0001
#define PT_FLAG_SCOPE_SYSTEM	0x0040
#define PT_FLAG_EXPLICIT_SCHED	0x0080
#define PT_FLAG_SUSPENDED	0x0100	/* In the suspended queue */

/* pt_cancel word */

#define	PT_CANCEL_DISABLED	__BIT(0)
#define	PT_CANCEL_ASYNC		__BIT(1)
#define	PT_CANCEL_PENDING	__BIT(2)
#define	PT_CANCEL_CANCELLED	__BIT(3)

#define PT_MAGIC	0x11110001
#define PT_DEAD		0xDEAD0001

#define PT_ATTR_MAGIC	0x22220002
#define PT_ATTR_DEAD	0xDEAD0002

extern size_t	pthread__stacksize;
extern size_t	pthread__guardsize;
extern size_t	pthread__pagesize;
extern int	pthread__nspins;
extern int	pthread__concurrency;
extern int 	pthread__osrev;
extern size_t 	pthread__unpark_max;
extern int	pthread_keys_max;

extern int	__uselibcstub;

struct pthread__waiter {
	struct pthread__waiter	*volatile next;
	lwpid_t			volatile lid;
};

/* Flag to be used in a ucontext_t's uc_flags indicating that
 * the saved register state is "user" state only, not full
 * trap state.
 */
#define _UC_USER_BIT		30
#define _UC_USER		(1LU << _UC_USER_BIT)

/* Utility functions */
void	pthread__unpark_all(pthread_queue_t *, pthread_t, pthread_mutex_t *)
    PTHREAD_HIDE;
void	pthread__unpark(pthread_queue_t *, pthread_t, pthread_mutex_t *)
    PTHREAD_HIDE;
int	pthread__park(pthread_t, pthread_mutex_t *, pthread_queue_t *,
		      const struct timespec *, int) PTHREAD_HIDE;
pthread_mutex_t *pthread__hashlock(volatile const void *) PTHREAD_HIDE;

/* Internal locking primitives */
void	pthread__lockprim_init(void) PTHREAD_HIDE;
void	pthread_lockinit(pthread_spin_t *) PTHREAD_HIDE;

static inline void pthread__spinlock(pthread_t, pthread_spin_t *)
    __attribute__((__always_inline__));
static inline void
pthread__spinlock(pthread_t self, pthread_spin_t *lock)
{
	if (__predict_true((*self->pt_lockops.plo_try)(lock)))
		return;
	(*self->pt_lockops.plo_lock)(lock);
}

static inline int pthread__spintrylock(pthread_t, pthread_spin_t *)
    __attribute__((__always_inline__));
static inline int
pthread__spintrylock(pthread_t self, pthread_spin_t *lock)
{
	return (*self->pt_lockops.plo_try)(lock);
}

static inline void pthread__spinunlock(pthread_t, pthread_spin_t *)
    __attribute__((__always_inline__));
static inline void
pthread__spinunlock(pthread_t self, pthread_spin_t *lock)
{
	(*self->pt_lockops.plo_unlock)(lock);
}

extern const struct pthread_lock_ops *pthread__lock_ops;

int	pthread__simple_locked_p(__cpu_simple_lock_t *) PTHREAD_HIDE;
#define	pthread__simple_lock_init(alp)	(*pthread__lock_ops->plo_init)(alp)
#define	pthread__simple_lock_try(alp)	(*pthread__lock_ops->plo_try)(alp)
#define	pthread__simple_unlock(alp)	(*pthread__lock_ops->plo_unlock)(alp)

void	pthread__testcancel(pthread_t) PTHREAD_HIDE;
int	pthread__find(pthread_t) PTHREAD_HIDE;

#ifndef PTHREAD_MD_INIT
#define PTHREAD_MD_INIT
#endif

#ifndef _INITCONTEXT_U_MD
#define _INITCONTEXT_U_MD(ucp)
#endif

#define _INITCONTEXT_U(ucp) do {					\
	(ucp)->uc_flags = _UC_CPU | _UC_STACK;				\
	_INITCONTEXT_U_MD(ucp)						\
	} while (0)


#if !defined(__HAVE_TLS_VARIANT_I) && !defined(__HAVE_TLS_VARIANT_II)
#error Either __HAVE_TLS_VARIANT_I or __HAVE_TLS_VARIANT_II must be defined
#endif

#ifdef _PTHREAD_GETTCB_EXT
struct tls_tcb *_PTHREAD_GETTCB_EXT(void);
#endif

static inline pthread_t __constfunc
pthread__self(void)
{
#if defined(_PTHREAD_GETTCB_EXT)
	struct tls_tcb * const tcb = _PTHREAD_GETTCB_EXT();
#elif defined(__HAVE___LWP_GETTCB_FAST)
	struct tls_tcb * const tcb = __lwp_gettcb_fast();
#else
	struct tls_tcb * const tcb = __lwp_getprivate_fast();
#endif
	return (pthread_t)tcb->tcb_pthread;
}

#define pthread__abort()						\
	pthread__assertfunc(__FILE__, __LINE__, __func__, "unreachable")

#define pthread__assert(e) do {						\
	if (__predict_false(!(e)))					\
       	       pthread__assertfunc(__FILE__, __LINE__, __func__, #e);	\
        } while (0)

#define pthread__error(err, msg, e) do {				\
	if (__predict_false(!(e))) {					\
       	       pthread__errorfunc(__FILE__, __LINE__, __func__, msg);	\
	       return (err);						\
	} 								\
        } while (0)

void 	*pthread_tsd_init(size_t *) PTHREAD_HIDE;
void	pthread__destroy_tsd(pthread_t) PTHREAD_HIDE;
void	pthread__copy_tsd(pthread_t) PTHREAD_HIDE;

__dead void	pthread__assertfunc(const char *, int, const char *, const char *)
			    PTHREAD_HIDE;
void	pthread__errorfunc(const char *, int, const char *, const char *, ...)
			    __printflike(4, 5) PTHREAD_HIDE;
char	*pthread__getenv(const char *) PTHREAD_HIDE;
__dead void	pthread__cancelled(void) PTHREAD_HIDE;
void	pthread__mutex_deferwake(pthread_t, pthread_mutex_t *,
    struct pthread__waiter *) PTHREAD_HIDE;
int	pthread__checkpri(int) PTHREAD_HIDE;
int	pthread__add_specific(pthread_t, pthread_key_t, const void *) PTHREAD_HIDE;

#ifndef pthread__smt_pause
#define	pthread__smt_pause()	__nothing
#endif
#ifndef pthread__smt_wait
#define	pthread__smt_wait()	__nothing
#endif
#ifndef pthread__smt_wake
#define	pthread__smt_wake()	__nothing
#endif

/*
 * Bits in the owner field of the lock that indicate lock state.  If the
 * WRITE_LOCKED bit is clear, then the owner field is actually a count of
 * the number of readers.
 */
#define	RW_HAS_WAITERS		0x01	/* lock has waiters */
#define	RW_WRITE_WANTED		0x02	/* >= 1 waiter is a writer */
#define	RW_WRITE_LOCKED		0x04	/* lock is currently write locked */
#define	RW_UNUSED		0x08	/* currently unused */

#define	RW_FLAGMASK		0x0f

#define	RW_READ_COUNT_SHIFT	4
#define	RW_READ_INCR		(1 << RW_READ_COUNT_SHIFT)
#define	RW_THREAD		((uintptr_t)-RW_READ_INCR)

#endif /* _LIB_PTHREAD_INT_H */
