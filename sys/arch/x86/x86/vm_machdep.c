/*	$NetBSD: vm_machdep.c,v 1.47 2025/04/24 01:50:39 riastradh Exp $	*/

/*-
 * Copyright (c) 1982, 1986 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department, and William Jolitz.
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
 *	@(#)vm_machdep.c	7.3 (Berkeley) 5/13/91
 */

/*-
 * Copyright (c) 1995 Charles M. Hannum.  All rights reserved.
 * Copyright (c) 1989, 1990 William Jolitz
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department, and William Jolitz.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	@(#)vm_machdep.c	7.3 (Berkeley) 5/13/91
 */

/*
 *	Utah $Hdr: vm_machdep.c 1.16.1.1 89/06/23$
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: vm_machdep.c,v 1.47 2025/04/24 01:50:39 riastradh Exp $");

#include "opt_mtrr.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <sys/core.h>
#include <sys/exec.h>
#include <sys/ptrace.h>

#include <uvm/uvm.h>

#include <machine/cpu.h>
#include <machine/gdt.h>
#include <machine/reg.h>
#include <machine/specialreg.h>

#ifdef MTRR
#include <machine/mtrr.h>
#endif

#include <x86/fpu.h>
#include <x86/dbregs.h>

extern struct pool x86_dbregspl;

void
cpu_proc_fork(struct proc *p1, struct proc *p2)
{

	p2->p_md.md_flags = p1->p_md.md_flags;
}

/*
 * cpu_lwp_fork: finish a new LWP (l2) operation.
 *
 * First LWP (l1) is the process being forked.  If it is &lwp0, then we
 * are creating a kthread, where return path and argument are specified
 * with `func' and `arg'.
 *
 * If an alternate user-level stack is requested (with non-zero values
 * in both the stack and stacksize arguments), then set up the user stack
 * pointer accordingly.
 */
void
cpu_lwp_fork(struct lwp *l1, struct lwp *l2, void *stack, size_t stacksize,
    void (*func)(void *), void *arg)
{
	struct pcb *pcb1, *pcb2;
	struct trapframe *tf;
	struct switchframe *sf;
	vaddr_t uv;

	KASSERT(l1 == curlwp || l1 == &lwp0);

	pcb1 = lwp_getpcb(l1);
	pcb2 = lwp_getpcb(l2);

	/* Copy the PCB from parent, except the FPU state. */
	memcpy(pcb2, pcb1, offsetof(struct pcb, pcb_savefpu));

	/* Fork the FPU state. */
	fpu_lwp_fork(l1, l2);

	/* Never inherit CPU Debug Registers */
	pcb2->pcb_dbregs = NULL;
	pcb2->pcb_flags &= ~PCB_DBREGS;

#if defined(XENPV)
	pcb2->pcb_iopl = IOPL_KPL;
#endif

	/*
	 * Set the kernel stack address (from the address to uarea) and
	 * trapframe address for child.
	 *
	 * Rig kernel stack so that it would start out in lwp_trampoline()
	 * and call child_return() with l2 as an argument.  This causes the
	 * newly-created child process to go directly to user level with a
	 * parent return value of 0 from fork(), while the parent process
	 * returns normally.
	 */
	uv = uvm_lwp_getuarea(l2);
	KASSERT(uv % PAGE_SIZE == 0);

#ifdef __x86_64__
#ifdef SVS
	pcb2->pcb_rsp0 = (uv + USPACE - PAGE_SIZE +
	    sizeof(struct trapframe));
	KASSERT((pcb2->pcb_rsp0 & 0xF) == 0);
#else
	pcb2->pcb_rsp0 = (uv + USPACE - 16);
#endif
	tf = (struct trapframe *)pcb2->pcb_rsp0 - 1;
#else
	pcb2->pcb_esp0 = (uv + USPACE - 16);
	tf = (struct trapframe *)pcb2->pcb_esp0 - 1;

	pcb2->pcb_iomap = NULL;
#endif
	l2->l_md.md_regs = tf;

	/*
	 * Copy the trapframe from parent, so that return to userspace
	 * will be to right address, with correct registers.
	 */
	memcpy(tf, l1->l_md.md_regs, sizeof(struct trapframe));

	/* Child LWP might get aston() before returning to userspace. */
	tf->tf_trapno = T_ASTFLT;

	/* If specified, set a different user stack for a child. */
	if (stack != NULL) {
#ifdef __x86_64__
		tf->tf_rsp = (uint64_t)stack + stacksize;
#else
		tf->tf_esp = (uint32_t)stack + stacksize;
#endif
	}

	l2->l_md.md_flags = l1->l_md.md_flags;
	KASSERT(l2->l_md.md_astpending == 0);

	sf = (struct switchframe *)tf - 1;

#ifdef __x86_64__
	sf->sf_r12 = (uint64_t)func;
	sf->sf_r13 = (uint64_t)arg;
	sf->sf_rip = (uint64_t)lwp_trampoline;
	pcb2->pcb_rsp = (uint64_t)sf;
	pcb2->pcb_rbp = (uint64_t)l2;
#else
	/*
	 * XXX Is there a reason sf->sf_edi isn't initialized here?
	 * Could this leak potentially sensitive information to new
	 * userspace processes?
	 */
	sf->sf_esi = (int)func;
	sf->sf_ebx = (int)arg;
	sf->sf_eip = (int)lwp_trampoline;
	pcb2->pcb_esp = (int)sf;
	pcb2->pcb_ebp = (int)l2;
#endif
}

/*
 * cpu_lwp_free is called from exit() to let machine-dependent
 * code free machine-dependent resources.  Note that this routine
 * must not block.  NB: this may be called with l != curlwp in
 * error paths.
 */
void
cpu_lwp_free(struct lwp *l, int proc)
{

	if (l != curlwp)
		return;

	/* Abandon the FPU state. */
	fpu_lwp_abandon(l);

	/* Abandon the dbregs state. */
	x86_dbregs_abandon(l);

#ifdef MTRR
	if (proc && l->l_proc->p_md.md_flags & MDP_USEDMTRR)
		mtrr_clean(l->l_proc);
#endif
}

/*
 * cpu_lwp_free2 is called when an LWP is being reaped.
 * This routine may block.
 */
void
cpu_lwp_free2(struct lwp *l)
{
	struct pcb *pcb;

	pcb = lwp_getpcb(l);
	KASSERT((pcb->pcb_flags & PCB_DBREGS) == 0);
	if (pcb->pcb_dbregs) {
		pool_put(&x86_dbregspl, pcb->pcb_dbregs);
		pcb->pcb_dbregs = NULL;
	}
}

/*
 * Convert kernel VA to physical address
 */
paddr_t
kvtop(void *addr)
{
	paddr_t pa;
	bool ret __diagused;

	ret = pmap_extract(pmap_kernel(), (vaddr_t)addr, &pa);
	KASSERT(ret == true);
	return pa;
}

/*
 * Map a user I/O request into kernel virtual address space.
 * Note: the pages are already locked by uvm_vslock(), so we
 * do not need to pass an access_type to pmap_enter().
 */
int
vmapbuf(struct buf *bp, vsize_t len)
{
	vaddr_t faddr, taddr, off;
	paddr_t fpa;

	KASSERT((bp->b_flags & B_PHYS) != 0);

	bp->b_saveaddr = bp->b_data;
	faddr = trunc_page((vaddr_t)bp->b_data);
	off = (vaddr_t)bp->b_data - faddr;
	len = round_page(off + len);
	taddr = uvm_km_alloc(phys_map, len, 0, UVM_KMF_VAONLY | UVM_KMF_WAITVA);
	bp->b_data = (void *)(taddr + off);
	/*
	 * The region is locked, so we expect that pmap_extract() will return
	 * true.
	 * XXX: unwise to expect this in a multithreaded environment.
	 * anything can happen to a pmap between the time we lock a
	 * region, release the pmap lock, and then relock it for
	 * the pmap_extract().
	 *
	 * no need to flush TLB since we expect nothing to be mapped
	 * where we just allocated (TLB will be flushed when our
	 * mapping is removed).
	 */
	while (len) {
		(void) pmap_extract(vm_map_pmap(&bp->b_proc->p_vmspace->vm_map),
		    faddr, &fpa);
		pmap_kenter_pa(taddr, fpa, VM_PROT_READ|VM_PROT_WRITE, 0);
		faddr += PAGE_SIZE;
		taddr += PAGE_SIZE;
		len -= PAGE_SIZE;
	}
	pmap_update(pmap_kernel());

	return 0;
}

/*
 * Unmap a previously-mapped user I/O request.
 */
void
vunmapbuf(struct buf *bp, vsize_t len)
{
	vaddr_t addr, off;

	KASSERT((bp->b_flags & B_PHYS) != 0);

	addr = trunc_page((vaddr_t)bp->b_data);
	off = (vaddr_t)bp->b_data - addr;
	len = round_page(off + len);
	pmap_kremove(addr, len);
	pmap_update(pmap_kernel());
	uvm_km_free(phys_map, addr, len, UVM_KMF_VAONLY);
	bp->b_data = bp->b_saveaddr;
	bp->b_saveaddr = 0;
}

#ifdef __HAVE_CPU_UAREA_ROUTINES
/*
 * Layout of the uarea:
 *    Page[0]        = PCB
 *    Page[1]        = RedZone
 *    Page[2]        = Stack
 *    Page[...]      = Stack
 *    Page[UPAGES-1] = Stack
 *    Page[UPAGES]   = RedZone
 * There is a redzone at the beginning of the stack, and another one at the
 * end. The former is to protect against deep recursions that could corrupt
 * the PCB, the latter to protect against severe stack overflows.
 */
void *
cpu_uarea_alloc(bool system)
{
	vaddr_t base, va;
	paddr_t pa;
	struct pcb *pcb;

	base = uvm_km_alloc(kernel_map, USPACE + PAGE_SIZE, 0,
	    UVM_KMF_WIRED|UVM_KMF_WAITVA);

	/*
	 * Prepare the FPU save area:
	 *
	 * 1. If this is a system thread, no save area.
	 *    XXX Allocate/free one in kthread_fpu_enter/exit_md.
	 *
	 * 2. If this is a user thread, and the fpu save size is large
	 *    enough, allocate an extra block of memory for it.
	 *
	 * 3. Otherwise, this is a user thread and the fpu save size
	 *    fits inside the pcb page, so use that.
	 *
	 * XXX Note that this is currently amd64-only -- if you extend
	 * this FPU save space allocation to i386, you'll need to
	 * remove the panic in fpuinit_mxcsr_mask on
	 * x86_fpu_save_separate_p and make pcb_savefpu a pointer
	 * indirection in struct pcb.
	 */
	pcb = (void *)base;
	if (system) {					/* (1) */
		pcb->pcb_savefpu = NULL;
	} else if (x86_fpu_save_separate_p()) {		/* (2) */
		__CTASSERT(PAGE_SIZE >= 64);
		/* No need to zero -- caller will initialize. */
		va = uvm_km_alloc(kernel_map, x86_fpu_save_size, PAGE_SIZE,
		    UVM_KMF_WIRED|UVM_KMF_WAITVA);
		pcb->pcb_savefpu = (void *)va;
	} else {					/* (3) */
		pcb->pcb_savefpu = &pcb->pcb_savefpusmall;
	}

	/* Page[1] = RedZone */
	va = base + PAGE_SIZE;
	if (!pmap_extract(pmap_kernel(), va, &pa)) {
		panic("%s: impossible, Page[1] unmapped", __func__);
	}
	pmap_kremove(va, PAGE_SIZE);
	uvm_pagefree(PHYS_TO_VM_PAGE(pa));

	/* Page[UPAGES] = RedZone */
	va = base + USPACE;
	if (!pmap_extract(pmap_kernel(), va, &pa)) {
		panic("%s: impossible, Page[UPAGES] unmapped", __func__);
	}
	pmap_kremove(va, PAGE_SIZE);
	uvm_pagefree(PHYS_TO_VM_PAGE(pa));

	pmap_update(pmap_kernel());

	return (void *)base;
}

bool
cpu_uarea_free(void *addr)
{
	const struct pcb *const pcb = addr;
	vaddr_t base = (vaddr_t)addr;

	/*
	 * If we allocated a separate FPU save area, free it.
	 */
	if (pcb->pcb_savefpu != NULL &&
	    pcb->pcb_savefpu != &pcb->pcb_savefpusmall) {
		KASSERTMSG(x86_fpu_save_separate_p(), "pcb=%p pcb_savefpu=%p",
		    pcb, pcb->pcb_savefpu);
		uvm_km_free(kernel_map, (vaddr_t)pcb->pcb_savefpu,
		    x86_fpu_save_size, UVM_KMF_WIRED);
	}

	KASSERT(!pmap_extract(pmap_kernel(), base + PAGE_SIZE, NULL));
	KASSERT(!pmap_extract(pmap_kernel(), base + USPACE, NULL));
	uvm_km_free(kernel_map, base, USPACE + PAGE_SIZE, UVM_KMF_WIRED);
	return true;
}
#endif /* __HAVE_CPU_UAREA_ROUTINES */
