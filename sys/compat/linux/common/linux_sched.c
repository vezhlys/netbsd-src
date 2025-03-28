/*	$NetBSD: linux_sched.c,v 1.83 2024/10/03 12:56:49 hannken Exp $	*/

/*-
 * Copyright (c) 1999, 2019 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center; by Matthias Scheler.
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
 * Linux compatibility module. Try to deal with scheduler related syscalls.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: linux_sched.c,v 1.83 2024/10/03 12:56:49 hannken Exp $");

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/syscallargs.h>
#include <sys/wait.h>
#include <sys/kauth.h>
#include <sys/ptrace.h>
#include <sys/atomic.h>

#include <sys/cpu.h>

#include <compat/linux/common/linux_types.h>
#include <compat/linux/common/linux_signal.h>
#include <compat/linux/common/linux_emuldata.h>
#include <compat/linux/common/linux_ipc.h>
#include <compat/linux/common/linux_sem.h>
#include <compat/linux/common/linux_exec.h>
#include <compat/linux/common/linux_machdep.h>

#include <compat/linux/linux_syscallargs.h>

#include <compat/linux/common/linux_sched.h>

static int linux_clone_nptl(struct lwp *, const struct linux_sys_clone_args *,
    register_t *);

/* Unlike Linux, dynamically calculate CPU mask size */
#define	LINUX_CPU_MASK_SIZE (sizeof(long) * ((ncpu + LONG_BIT - 1) / LONG_BIT))

#if DEBUG_LINUX
#define DPRINTF(x, ...) uprintf(x, __VA_ARGS__)
#else
#define DPRINTF(x, ...)
#endif

static void
linux_child_return(void *arg)
{
	struct lwp *l = arg;
	struct proc *p = l->l_proc;
	struct linux_emuldata *led = l->l_emuldata;
	void *ctp = led->led_child_tidptr;
	int error;

	if (ctp) {
		if ((error = copyout(&p->p_pid, ctp, sizeof(p->p_pid))) != 0)
			printf("%s: LINUX_CLONE_CHILD_SETTID "
			    "failed (child_tidptr = %p, tid = %d error =%d)\n",
			    __func__, ctp, p->p_pid, error);
	}
	child_return(arg);
}

int
linux_sys_clone(struct lwp *l, const struct linux_sys_clone_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int) flags;
		syscallarg(void *) stack;
		syscallarg(void *) parent_tidptr;
		syscallarg(void *) tls;
		syscallarg(void *) child_tidptr;
	} */
	struct linux_emuldata *led;
	int flags, sig, error;

	/*
	 * We don't support the Linux CLONE_PID or CLONE_PTRACE flags.
	 */
	if (SCARG(uap, flags) & (LINUX_CLONE_PID|LINUX_CLONE_PTRACE))
		return EINVAL;

	/*
	 * Thread group implies shared signals. Shared signals
	 * imply shared VM. This matches what Linux kernel does.
	 */
	if (SCARG(uap, flags) & LINUX_CLONE_THREAD
	    && (SCARG(uap, flags) & LINUX_CLONE_SIGHAND) == 0)
		return EINVAL;
	if (SCARG(uap, flags) & LINUX_CLONE_SIGHAND
	    && (SCARG(uap, flags) & LINUX_CLONE_VM) == 0)
		return EINVAL;

	/*
	 * The thread group flavor is implemented totally differently.
	 */
	if (SCARG(uap, flags) & LINUX_CLONE_THREAD)
		return linux_clone_nptl(l, uap, retval);

	flags = 0;
	if (SCARG(uap, flags) & LINUX_CLONE_VM)
		flags |= FORK_SHAREVM;
	if (SCARG(uap, flags) & LINUX_CLONE_FS)
		flags |= FORK_SHARECWD;
	if (SCARG(uap, flags) & LINUX_CLONE_FILES)
		flags |= FORK_SHAREFILES;
	if (SCARG(uap, flags) & LINUX_CLONE_SIGHAND)
		flags |= FORK_SHARESIGS;
	if (SCARG(uap, flags) & LINUX_CLONE_VFORK)
		flags |= FORK_PPWAIT;

	sig = SCARG(uap, flags) & LINUX_CLONE_CSIGNAL;
	if (sig < 0 || sig >= LINUX__NSIG)
		return EINVAL;
	sig = linux_to_native_signo[sig];

	if (SCARG(uap, flags) & LINUX_CLONE_CHILD_SETTID) {
		led = l->l_emuldata;
		led->led_child_tidptr = SCARG(uap, child_tidptr);
	}

	/*
	 * Note that Linux does not provide a portable way of specifying
	 * the stack area; the caller must know if the stack grows up
	 * or down.  So, we pass a stack size of 0, so that the code
	 * that makes this adjustment is a noop.
	 */
	if ((error = fork1(l, flags, sig, SCARG(uap, stack), 0,
	    linux_child_return, NULL, retval)) != 0) {
		DPRINTF("%s: fork1: error %d\n", __func__, error);
		return error;
	}

	return 0;
}


int
linux_sys_clone3(struct lwp *l, const struct linux_sys_clone3_args *uap, register_t *retval)
{
	struct linux_user_clone3_args cl_args;
	struct linux_sys_clone_args clone_args;
	int error;

	if (SCARG(uap, size) != sizeof(cl_args)) {
	    DPRINTF("%s: Invalid size less or more\n", __func__);
	    return EINVAL;
	}

	error = copyin(SCARG(uap, cl_args), &cl_args, SCARG(uap, size));
	if (error) {
		DPRINTF("%s: Copyin failed: %d\n", __func__, error);
		return error;
	}

	DPRINTF("%s: Flags: %#jx\n", __func__, (intmax_t)cl_args.flags);

	/* Define allowed flags */
	if (cl_args.flags & LINUX_CLONE_UNIMPLEMENTED_FLAGS) {
		DPRINTF("%s: Unsupported flags for clone3: %#" PRIx64 "\n",
		    __func__, cl_args.flags & LINUX_CLONE_UNIMPLEMENTED_FLAGS);
		return EOPNOTSUPP;
	}
	if (cl_args.flags & ~LINUX_CLONE_ALLOWED_FLAGS) {
		DPRINTF("%s: Disallowed flags for clone3: %#" PRIx64 "\n",
		    __func__, cl_args.flags & ~LINUX_CLONE_ALLOWED_FLAGS);
		return EINVAL;
	}

#if 0
	// XXX: this is wrong, exit_signal is the signal to deliver to the
	// process upon exit.
	if ((cl_args.exit_signal & ~(uint64_t)LINUX_CLONE_CSIGNAL) != 0){
		DPRINTF("%s: Disallowed flags for clone3: %#x\n", __func__,
		    cl_args.exit_signal & ~(uint64_t)LINUX_CLONE_CSIGNAL);
		return EINVAL;
	}
#endif

	if (cl_args.stack == 0 && cl_args.stack_size != 0) {
		DPRINTF("%s: Stack is NULL but stack size is not 0\n",
		    __func__);
		return EINVAL;
	}
	if (cl_args.stack != 0 && cl_args.stack_size == 0) {
		DPRINTF("%s: Stack is not NULL but stack size is 0\n",
		    __func__);
		return EINVAL;
	}

	int flags = cl_args.flags & LINUX_CLONE_ALLOWED_FLAGS;
#if 0
	int sig = cl_args.exit_signal & LINUX_CLONE_CSIGNAL;
#endif
	// XXX: Pidfd member handling
	// XXX: we don't have cgroups
	// XXX: what to do with tid_set and tid_set_size
	// XXX: clone3 has stacksize, instead implement clone as a clone3
	// wrapper.
	SCARG(&clone_args, flags) = flags;
	SCARG(&clone_args, stack) = (void *)(uintptr_t)cl_args.stack;
	SCARG(&clone_args, parent_tidptr) =
	    (void *)(intptr_t)cl_args.parent_tid;
	SCARG(&clone_args, tls) =
	    (void *)(intptr_t)cl_args.tls;
	SCARG(&clone_args, child_tidptr) =
	    (void *)(intptr_t)cl_args.child_tid;

	return linux_sys_clone(l, &clone_args, retval);
}

static int
linux_clone_nptl(struct lwp *l, const struct linux_sys_clone_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) flags;
		syscallarg(void *) stack;
		syscallarg(void *) parent_tidptr;
		syscallarg(void *) tls;
		syscallarg(void *) child_tidptr;
	} */
	struct proc *p;
	struct lwp *l2;
	struct linux_emuldata *led;
	void *parent_tidptr, *tls, *child_tidptr;
	vaddr_t uaddr;
	lwpid_t lid;
	int flags, error;

	p = l->l_proc;
	flags = SCARG(uap, flags);
	parent_tidptr = SCARG(uap, parent_tidptr);
	tls = SCARG(uap, tls);
	child_tidptr = SCARG(uap, child_tidptr);

	uaddr = uvm_uarea_alloc();
	if (__predict_false(uaddr == 0)) {
		return ENOMEM;
	}

	error = lwp_create(l, p, uaddr, LWP_DETACHED,
	    SCARG(uap, stack), 0, child_return, NULL, &l2, l->l_class,
	    &l->l_sigmask, &l->l_sigstk);
	if (__predict_false(error)) {
		DPRINTF("%s: lwp_create error=%d\n", __func__, error);
		uvm_uarea_free(uaddr);
		return error;
	}
	lid = l2->l_lid;

	/* LINUX_CLONE_CHILD_CLEARTID: clear TID in child's memory on exit() */
	if (flags & LINUX_CLONE_CHILD_CLEARTID) {
		led = l2->l_emuldata;
		led->led_clear_tid = child_tidptr;
	}

	/* LINUX_CLONE_PARENT_SETTID: store child's TID in parent's memory */
	if (flags & LINUX_CLONE_PARENT_SETTID) {
		if ((error = copyout(&lid, parent_tidptr, sizeof(lid))) != 0)
			printf("%s: LINUX_CLONE_PARENT_SETTID "
			    "failed (parent_tidptr = %p tid = %d error=%d)\n",
			    __func__, parent_tidptr, lid, error);
	}

	/* LINUX_CLONE_CHILD_SETTID: store child's TID in child's memory  */
	if (flags & LINUX_CLONE_CHILD_SETTID) {
		if ((error = copyout(&lid, child_tidptr, sizeof(lid))) != 0)
			printf("%s: LINUX_CLONE_CHILD_SETTID "
			    "failed (child_tidptr = %p, tid = %d error=%d)\n",
			    __func__, child_tidptr, lid, error);
	}

	if (flags & LINUX_CLONE_SETTLS) {
		error = LINUX_LWP_SETPRIVATE(l2, tls);
		if (error) {
			DPRINTF("%s: LINUX_LWP_SETPRIVATE %d\n", __func__,
			    error);
			lwp_exit(l2);
			return error;
		}
	}

	/* Set the new LWP running. */
	lwp_start(l2, 0);

	retval[0] = lid;
	retval[1] = 0;
	return 0;
}

/*
 * linux realtime priority
 *
 * - SCHED_RR and SCHED_FIFO tasks have priorities [1,99].
 *
 * - SCHED_OTHER tasks don't have realtime priorities.
 *   in particular, sched_param::sched_priority is always 0.
 */

#define	LINUX_SCHED_RTPRIO_MIN	1
#define	LINUX_SCHED_RTPRIO_MAX	99

static int
sched_linux2native(int linux_policy, struct linux_sched_param *linux_params,
    int *native_policy, struct sched_param *native_params)
{

	switch (linux_policy) {
	case LINUX_SCHED_OTHER:
		if (native_policy != NULL) {
			*native_policy = SCHED_OTHER;
		}
		break;

	case LINUX_SCHED_FIFO:
		if (native_policy != NULL) {
			*native_policy = SCHED_FIFO;
		}
		break;

	case LINUX_SCHED_RR:
		if (native_policy != NULL) {
			*native_policy = SCHED_RR;
		}
		break;

	default:
		return EINVAL;
	}

	if (linux_params != NULL) {
		int prio = linux_params->sched_priority;

		KASSERT(native_params != NULL);

		if (linux_policy == LINUX_SCHED_OTHER) {
			if (prio != 0) {
				return EINVAL;
			}
			native_params->sched_priority = PRI_NONE; /* XXX */
		} else {
			if (prio < LINUX_SCHED_RTPRIO_MIN ||
			    prio > LINUX_SCHED_RTPRIO_MAX) {
				return EINVAL;
			}
			native_params->sched_priority =
			    (prio - LINUX_SCHED_RTPRIO_MIN)
			    * (SCHED_PRI_MAX - SCHED_PRI_MIN)
			    / (LINUX_SCHED_RTPRIO_MAX - LINUX_SCHED_RTPRIO_MIN)
			    + SCHED_PRI_MIN;
		}
	}

	return 0;
}

static int
sched_native2linux(int native_policy, struct sched_param *native_params,
    int *linux_policy, struct linux_sched_param *linux_params)
{

	switch (native_policy) {
	case SCHED_OTHER:
		if (linux_policy != NULL) {
			*linux_policy = LINUX_SCHED_OTHER;
		}
		break;

	case SCHED_FIFO:
		if (linux_policy != NULL) {
			*linux_policy = LINUX_SCHED_FIFO;
		}
		break;

	case SCHED_RR:
		if (linux_policy != NULL) {
			*linux_policy = LINUX_SCHED_RR;
		}
		break;

	default:
		panic("%s: unknown policy %d\n", __func__, native_policy);
	}

	if (native_params != NULL) {
		int prio = native_params->sched_priority;

		KASSERT(prio >= SCHED_PRI_MIN);
		KASSERT(prio <= SCHED_PRI_MAX);
		KASSERT(linux_params != NULL);

		memset(linux_params, 0, sizeof(*linux_params));

		DPRINTF("%s: native: policy %d, priority %d\n",
		    __func__, native_policy, prio);

		if (native_policy == SCHED_OTHER) {
			linux_params->sched_priority = 0;
		} else {
			linux_params->sched_priority =
			    (prio - SCHED_PRI_MIN)
			    * (LINUX_SCHED_RTPRIO_MAX - LINUX_SCHED_RTPRIO_MIN)
			    / (SCHED_PRI_MAX - SCHED_PRI_MIN)
			    + LINUX_SCHED_RTPRIO_MIN;
		}
		DPRINTF("%s: linux: policy %d, priority %d\n",
		    __func__, -1, linux_params->sched_priority);
	}

	return 0;
}

int
linux_sys_sched_setparam(struct lwp *l, const struct linux_sys_sched_setparam_args *uap, register_t *retval)
{
	/* {
		syscallarg(linux_pid_t) pid;
		syscallarg(const struct linux_sched_param *) sp;
	} */
	int error, policy;
	struct linux_sched_param lp;
	struct sched_param sp;

	if (SCARG(uap, pid) < 0 || SCARG(uap, sp) == NULL) {
		error = EINVAL;
		goto out;
	}

	error = copyin(SCARG(uap, sp), &lp, sizeof(lp));
	if (error)
		goto out;

	/* We need the current policy in Linux terms. */
	error = do_sched_getparam(SCARG(uap, pid), 0, &policy, NULL);
	if (error)
		goto out;
	error = sched_native2linux(policy, NULL, &policy, NULL);
	if (error)
		goto out;

	error = sched_linux2native(policy, &lp, &policy, &sp);
	if (error)
		goto out;

	error = do_sched_setparam(SCARG(uap, pid), 0, policy, &sp);
	if (error)
		goto out;

 out:
	return error;
}

int
linux_sys_sched_getparam(struct lwp *l, const struct linux_sys_sched_getparam_args *uap, register_t *retval)
{
	/* {
		syscallarg(linux_pid_t) pid;
		syscallarg(struct linux_sched_param *) sp;
	} */
	struct linux_sched_param lp;
	struct sched_param sp;
	int error, policy;

	if (SCARG(uap, pid) < 0 || SCARG(uap, sp) == NULL) {
		error = EINVAL;
		goto out;
	}

	error = do_sched_getparam(SCARG(uap, pid), 0, &policy, &sp);
	if (error)
		goto out;
	DPRINTF("%s: native: policy %d, priority %d\n",
	    __func__, policy, sp.sched_priority);

	error = sched_native2linux(policy, &sp, NULL, &lp);
	if (error)
		goto out;
	DPRINTF("%s: linux: policy %d, priority %d\n",
	    __func__, policy, lp.sched_priority);

	error = copyout(&lp, SCARG(uap, sp), sizeof(lp));
	if (error)
		goto out;

 out:
	return error;
}

int
linux_sys_sched_setscheduler(struct lwp *l, const struct linux_sys_sched_setscheduler_args *uap, register_t *retval)
{
	/* {
		syscallarg(linux_pid_t) pid;
		syscallarg(int) policy;
		syscallarg(cont struct linux_sched_param *) sp;
	} */
	int error, policy;
	struct linux_sched_param lp;
	struct sched_param sp;

	if (SCARG(uap, pid) < 0 || SCARG(uap, sp) == NULL) {
		error = EINVAL;
		goto out;
	}

	error = copyin(SCARG(uap, sp), &lp, sizeof(lp));
	if (error)
		goto out;
	DPRINTF("%s: linux: policy %d, priority %d\n",
	    __func__, SCARG(uap, policy), lp.sched_priority);

	error = sched_linux2native(SCARG(uap, policy), &lp, &policy, &sp);
	if (error)
		goto out;
	DPRINTF("%s: native: policy %d, priority %d\n",
	    __func__, policy, sp.sched_priority);

	error = do_sched_setparam(SCARG(uap, pid), 0, policy, &sp);
	if (error)
		goto out;

 out:
	return error;
}

int
linux_sys_sched_getscheduler(struct lwp *l, const struct linux_sys_sched_getscheduler_args *uap, register_t *retval)
{
	/* {
		syscallarg(linux_pid_t) pid;
	} */
	int error, policy;

	*retval = -1;

	error = do_sched_getparam(SCARG(uap, pid), 0, &policy, NULL);
	if (error)
		goto out;

	error = sched_native2linux(policy, NULL, &policy, NULL);
	if (error)
		goto out;

	*retval = policy;

 out:
	return error;
}

int
linux_sys_sched_yield(struct lwp *l, const void *v, register_t *retval)
{

	yield();
	return 0;
}

int
linux_sys_sched_get_priority_max(struct lwp *l, const struct linux_sys_sched_get_priority_max_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) policy;
	} */

	switch (SCARG(uap, policy)) {
	case LINUX_SCHED_OTHER:
		*retval = 0;
		break;
	case LINUX_SCHED_FIFO:
	case LINUX_SCHED_RR:
		*retval = LINUX_SCHED_RTPRIO_MAX;
		break;
	default:
		return EINVAL;
	}

	return 0;
}

int
linux_sys_sched_get_priority_min(struct lwp *l, const struct linux_sys_sched_get_priority_min_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) policy;
	} */

	switch (SCARG(uap, policy)) {
	case LINUX_SCHED_OTHER:
		*retval = 0;
		break;
	case LINUX_SCHED_FIFO:
	case LINUX_SCHED_RR:
		*retval = LINUX_SCHED_RTPRIO_MIN;
		break;
	default:
		return EINVAL;
	}

	return 0;
}

int
linux_sys_exit(struct lwp *l, const struct linux_sys_exit_args *uap, register_t *retval)
{

	lwp_exit(l);
	return 0;
}

#ifndef __m68k__
/* Present on everything but m68k */
int
linux_sys_exit_group(struct lwp *l, const struct linux_sys_exit_group_args *uap, register_t *retval)
{

	return sys_exit(l, (const void *)uap, retval);
}
#endif /* !__m68k__ */

int
linux_sys_set_tid_address(struct lwp *l, const struct linux_sys_set_tid_address_args *uap, register_t *retval)
{
	/* {
		syscallarg(int *) tidptr;
	} */
	struct linux_emuldata *led;

	led = (struct linux_emuldata *)l->l_emuldata;
	led->led_clear_tid = SCARG(uap, tid);
	*retval = l->l_lid;

	return 0;
}

/* ARGUSED1 */
int
linux_sys_gettid(struct lwp *l, const void *v, register_t *retval)
{

	*retval = l->l_lid;
	return 0;
}

/*
 * The affinity syscalls assume that the layout of our cpu kcpuset is
 * the same as linux's: a linear bitmask.
 */
int
linux_sys_sched_getaffinity(struct lwp *l, const struct linux_sys_sched_getaffinity_args *uap, register_t *retval)
{
	/* {
		syscallarg(linux_pid_t) pid;
		syscallarg(unsigned int) len;
		syscallarg(unsigned long *) mask;
	} */
	struct proc *p;
	struct lwp *t;
	kcpuset_t *kcset;
	size_t size;
	cpuid_t i;
	int error;

	size = LINUX_CPU_MASK_SIZE;
	if (SCARG(uap, len) < size)
		return EINVAL;

	if (SCARG(uap, pid) == 0) {
		p = curproc;
		mutex_enter(p->p_lock);
		t = curlwp;
	} else {
		t = lwp_find2(-1, SCARG(uap, pid));
		if (__predict_false(t == NULL)) {
			return ESRCH;
		}
		p = t->l_proc;
		KASSERT(mutex_owned(p->p_lock));
	}

	/* Check the permission */
	if (kauth_authorize_process(l->l_cred,
	    KAUTH_PROCESS_SCHEDULER_GETAFFINITY, p, NULL, NULL, NULL)) {
		mutex_exit(p->p_lock);
		return EPERM;
	}

	kcpuset_create(&kcset, true);
	lwp_lock(t);
	if (t->l_affinity != NULL)
		kcpuset_copy(kcset, t->l_affinity);
	else {
		/*
		 * All available CPUs should be masked when affinity has not
		 * been set.
		 */
		kcpuset_zero(kcset);
		for (i = 0; i < ncpu; i++)
			kcpuset_set(kcset, i);
	}
	lwp_unlock(t);
	mutex_exit(p->p_lock);
	error = kcpuset_copyout(kcset, (cpuset_t *)SCARG(uap, mask), size);
	kcpuset_unuse(kcset, NULL);
	*retval = size;
	return error;
}

int
linux_sys_sched_setaffinity(struct lwp *l, const struct linux_sys_sched_setaffinity_args *uap, register_t *retval)
{
	/* {
		syscallarg(linux_pid_t) pid;
		syscallarg(unsigned int) len;
		syscallarg(unsigned long *) mask;
	} */
	struct sys__sched_setaffinity_args ssa;
	size_t size;
	pid_t pid;
	lwpid_t lid;

	size = LINUX_CPU_MASK_SIZE;
	if (SCARG(uap, len) < size)
		return EINVAL;

	lid = SCARG(uap, pid);
	if (lid != 0) {
		/* Get the canonical PID for the process. */
		mutex_enter(&proc_lock);
		struct proc *p = proc_find_lwpid(SCARG(uap, pid));
		if (p == NULL) {
			mutex_exit(&proc_lock);
			return ESRCH;
		}
		pid = p->p_pid;
		mutex_exit(&proc_lock);
	} else {
		pid = curproc->p_pid;
		lid = curlwp->l_lid;
	}

	SCARG(&ssa, pid) = pid;
	SCARG(&ssa, lid) = lid;
	SCARG(&ssa, size) = size;
	SCARG(&ssa, cpuset) = (cpuset_t *)SCARG(uap, mask);

	return sys__sched_setaffinity(l, &ssa, retval);
}
