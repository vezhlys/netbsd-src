/*	$NetBSD: booke_pmap.c,v 1.39 2024/09/24 07:29:55 skrll Exp $	*/
/*-
 * Copyright (c) 2010, 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Raytheon BBN Technologies Corp and Defense Advanced Research Projects
 * Agency and which was developed by Matt Thomas of 3am Software Foundry.
 *
 * This material is based upon work supported by the Defense Advanced Research
 * Projects Agency and Space and Naval Warfare Systems Center, Pacific, under
 * Contract No. N66001-09-C-2073.
 * Approved for Public Release, Distribution Unlimited
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

#define __PMAP_PRIVATE

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: booke_pmap.c,v 1.39 2024/09/24 07:29:55 skrll Exp $");

#ifdef _KERNEL_OPT
#include "opt_multiprocessor.h"
#include "opt_pmap.h"
#endif

#include <sys/param.h>
#include <sys/kcore.h>
#include <sys/buf.h>
#include <sys/mutex.h>

#include <uvm/uvm.h>

#include <machine/pmap.h>

PMAP_COUNTER(zeroed_pages, "pages zeroed");
PMAP_COUNTER(copied_pages, "pages copied");

CTASSERT(sizeof(pmap_segtab_t) == NBPG);

void
pmap_procwr(struct proc *p, vaddr_t va, size_t len)
{
	struct pmap * const pmap = p->p_vmspace->vm_map.pmap;
	vsize_t off = va & PAGE_MASK;

	kpreempt_disable();
	for (const vaddr_t eva = va + len; va < eva; off = 0) {
		const vaddr_t segeva = uimin(va + len, va - off + PAGE_SIZE);
		pt_entry_t * const ptep = pmap_pte_lookup(pmap, va);
		if (ptep == NULL) {
			va = segeva;
			continue;
		}
		pt_entry_t pt_entry = *ptep;
		if (!pte_valid_p(pt_entry) || !pte_exec_p(pt_entry)) {
			va = segeva;
			continue;
		}
		kpreempt_enable();
		dcache_wb(pte_to_paddr(pt_entry) + off, segeva - va);
		icache_inv(pte_to_paddr(pt_entry) + off, segeva - va);
		kpreempt_disable();
		va = segeva;
	}
	kpreempt_enable();
}

void
pmap_md_page_syncicache(struct vm_page_md *mdpg, const kcpuset_t *onproc)
{
	KASSERT(VM_PAGEMD_VMPAGE_P(mdpg));

	struct vm_page * const pg = VM_MD_TO_PAGE(mdpg);

	/*
	 * If onproc is empty, we could do a
	 * pmap_page_protect(pg, VM_PROT_NONE) and remove all
	 * mappings of the page and clear its execness.  Then
	 * the next time page is faulted, it will get icache
	 * synched.  But this is easier. :)
	 */
	const paddr_t pa = VM_PAGE_TO_PHYS(pg);
	dcache_wb_page(pa);
	icache_inv_page(pa);
}

vaddr_t
pmap_md_direct_map_paddr(paddr_t pa)
{
	return (vaddr_t) pa;
}

bool
pmap_md_direct_mapped_vaddr_p(vaddr_t va)
{
	return va < VM_MIN_KERNEL_ADDRESS || VM_MAX_KERNEL_ADDRESS <= va;
}

paddr_t
pmap_md_direct_mapped_vaddr_to_paddr(vaddr_t va)
{
	return (paddr_t) va;
}

#ifdef PMAP_MINIMALTLB
static pt_entry_t *
pmap_kvtopte(const pmap_segtab_t *stb, vaddr_t va)
{
	const vaddr_t segtab_mask = PMAP_SEGTABSIZE - 1;
	const size_t idx = (va >> SEGSHIFT) & segtab_mask;
	pmap_ptpage_t * const ppg = stb->seg_ppg[idx];
	if (ppg == NULL)
		return NULL;
	const size_t pte_idx = (va >> PGSHIFT) & (NPTEPG - 1);

	return &ppg->ppg_ptes[pte_idx];
}

vaddr_t
pmap_kvptefill(vaddr_t sva, vaddr_t eva, pt_entry_t pt_entry)
{
	pmap_segtab_t * const stb = &pmap_kern_segtab;
	KASSERT(sva == trunc_page(sva));
	pt_entry_t *ptep = pmap_kvtopte(stb, sva);
	for (; sva < eva; sva += NBPG) {
		*ptep++ = pt_entry ? (sva | pt_entry) : 0;
	}
	return sva;
}
#endif

/*
 *	Bootstrap the system enough to run with virtual memory.
 *	firstaddr is the first unused kseg0 address (not page aligned).
 */
vaddr_t
pmap_bootstrap(vaddr_t startkernel, vaddr_t endkernel,
	phys_ram_seg_t *avail, size_t cnt)
{
	pmap_segtab_t * const stb = &pmap_kern_segtab;

	KASSERT(endkernel == trunc_page(endkernel));

	/* common initialization */
	pmap_bootstrap_common();

	/* init the lock */
	pmap_tlb_info_init(&pmap_tlb0_info);

	/*
	 * Compute the number of pages kmem_arena will have.
	 */
	kmeminit_nkmempages();

	/*
	 * Figure out how many PTE's are necessary to map the kernel.
	 * We also reserve space for kmem_alloc_pageable() for vm_fork().
	 */

	/* Get size of buffer cache and set an upper limit */
	buf_setvalimit((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) / 8);
	vsize_t bufsz = buf_memcalc();
	buf_setvalimit(bufsz);

	vsize_t kv_nsegtabs = pmap_round_seg(VM_PHYS_SIZE
	    + (ubc_nwins << ubc_winshift)
	    + bufsz
	    + 16 * NCARGS
	    + pager_map_size
	    + maxproc * USPACE
	    + NBPG * nkmempages) >> SEGSHIFT;

	/*
	 * Initialize `FYI' variables.	Note we're relying on
	 * the fact that BSEARCH sorts the vm_physmem[] array
	 * for us.  Must do this before uvm_pageboot_alloc()
	 * can be called.
	 */
	pmap_limits.avail_start = uvm_physseg_get_start(uvm_physseg_get_first()) << PGSHIFT;
	pmap_limits.avail_end = uvm_physseg_get_end(uvm_physseg_get_last()) << PGSHIFT;
	const size_t max_nsegtabs =
	    (pmap_round_seg(VM_MAX_KERNEL_ADDRESS)
		- pmap_trunc_seg(VM_MIN_KERNEL_ADDRESS)) / NBSEG;
	if (kv_nsegtabs >= max_nsegtabs) {
		pmap_limits.virtual_end = VM_MAX_KERNEL_ADDRESS;
		kv_nsegtabs = max_nsegtabs;
	} else {
		pmap_limits.virtual_end = VM_MIN_KERNEL_ADDRESS
		    + kv_nsegtabs * NBSEG;
	}

	/* update the top of the kernel VM - pmap_growkernel not required */
	pmap_curmaxkvaddr = pmap_limits.virtual_end;

	/*
	 * Now actually allocate the kernel PTE array (must be done
	 * after virtual_end is initialized).
	 */
	const vaddr_t kv_segtabs = avail[0].start;
	KASSERT(kv_segtabs == endkernel);
	KASSERT(avail[0].size >= NBPG * kv_nsegtabs);
	printf(" kv_nsegtabs=%#"PRIxVSIZE, kv_nsegtabs);
	printf(" kv_segtabs=%#"PRIxVADDR, kv_segtabs);
	avail[0].start += NBPG * kv_nsegtabs;
	avail[0].size -= NBPG * kv_nsegtabs;
	endkernel += NBPG * kv_nsegtabs;

	/*
	 * Initialize the kernel's two-level page level.  This only wastes
	 * an extra page for the segment table and allows the user/kernel
	 * access to be common.
	 */

	pmap_ptpage_t **ppg_p = &stb->seg_ppg[VM_MIN_KERNEL_ADDRESS >> SEGSHIFT];
	pmap_ptpage_t *ppg = (void *)kv_segtabs;
	memset(ppg, 0, NBPG * kv_nsegtabs);
	for (size_t i = 0; i < kv_nsegtabs; i++, ppg++) {
		*ppg_p++ = ppg;
	}

#ifdef PMAP_MINIMALTLB
	const vsize_t dm_nsegtabs = (physmem + NPTEPG - 1) / NPTEPG;
	const vaddr_t dm_segtabs = avail[0].start;
	printf(" dm_nsegtabs=%#"PRIxVSIZE, dm_nsegtabs);
	printf(" dm_segtabs=%#"PRIxVADDR, dm_segtabs);
	KASSERT(dm_segtabs == endkernel);
	KASSERT(avail[0].size >= NBPG * dm_nsegtabs);
	avail[0].start += NBPG * dm_nsegtabs;
	avail[0].size -= NBPG * dm_nsegtabs;
	endkernel += NBPG * dm_nsegtabs;

	ppg_p = stb->seg_ppg;
	ppg = (void *)dm_segtabs;
	memset(ppg, 0, NBPG * dm_nsegtabs);
	for (size_t i = 0; i < dm_nsegtabs; i++, ppg_p++, ppg++) {
		*ppg_p = ppg;
	}

	/*
	 */
	extern uint32_t _fdata[], _etext[];
	vaddr_t va;

	/* Now make everything before the kernel inaccessible. */
	va = pmap_kvptefill(NBPG, startkernel, 0);

	/* Kernel text is readonly & executable */
	va = pmap_kvptefill(va, round_page((vaddr_t)_etext),
	    PTE_M | PTE_xR | PTE_xX);

	/* Kernel .rdata is readonly */
	va = pmap_kvptefill(va, trunc_page((vaddr_t)_fdata), PTE_M | PTE_xR);

	/* Kernel .data/.bss + page tables are read-write */
	va = pmap_kvptefill(va, round_page(endkernel), PTE_M | PTE_xR | PTE_xW);

	/* message buffer page table pages are read-write */
	(void) pmap_kvptefill(msgbuf_paddr, msgbuf_paddr+round_page(MSGBUFSIZE),
	    PTE_M | PTE_xR | PTE_xW);
#endif

	for (size_t i = 0; i < cnt; i++) {
		printf(" uvm_page_physload(%#lx,%#lx,%#lx,%#lx,%d)",
		    atop(avail[i].start),
		    atop(avail[i].start + avail[i].size) - 1,
		    atop(avail[i].start),
		    atop(avail[i].start + avail[i].size) - 1,
		    VM_FREELIST_DEFAULT);
		uvm_page_physload(
		    atop(avail[i].start),
		    atop(avail[i].start + avail[i].size) - 1,
		    atop(avail[i].start),
		    atop(avail[i].start + avail[i].size) - 1,
		    VM_FREELIST_DEFAULT);
	}

	pmap_pvlist_lock_init(curcpu()->ci_ci.dcache_line_size);

	/*
	 * Initialize the pools.
	 */
	pool_init(&pmap_pmap_pool, PMAP_SIZE, 0, 0, 0, "pmappl",
	    &pool_allocator_nointr, IPL_NONE);
	pool_init(&pmap_pv_pool, sizeof(struct pv_entry), 0, 0, 0, "pvpl",
	    &pmap_pv_page_allocator, IPL_NONE);

	tlb_set_asid(KERNEL_PID, pmap_kernel());

	return endkernel;
}

struct vm_page *
pmap_md_alloc_poolpage(int flags)
{

	/*
	 * Any managed page works for us.
	 */
	return uvm_pagealloc(NULL, 0, NULL, flags);
}

vaddr_t
pmap_md_map_poolpage(paddr_t pa, vsize_t size)
{
	const vaddr_t sva = (vaddr_t) pa;
#ifdef PMAP_MINIMALTLB
	const vaddr_t eva = sva + size;
	pmap_kvptefill(sva, eva, PTE_M | PTE_xR | PTE_xW);
#endif
	return sva;
}

void
pmap_md_unmap_poolpage(vaddr_t va, vsize_t size)
{
#ifdef PMAP_MINIMALTLB
	struct pmap * const pm = pmap_kernel();
	const vaddr_t eva = va + size;
	pmap_kvptefill(va, eva, 0);
	for (;va < eva; va += NBPG) {
		pmap_tlb_invalidate_addr(pm, va);
	}
	pmap_update(pm);
#endif
}

void
pmap_zero_page(paddr_t pa)
{
	PMAP_COUNT(zeroed_pages);
	vaddr_t va = pmap_md_map_poolpage(pa, NBPG);
	dcache_zero_page(va);

	KASSERT(!VM_PAGEMD_EXECPAGE_P(VM_PAGE_TO_MD(PHYS_TO_VM_PAGE(va))));
	pmap_md_unmap_poolpage(va, NBPG);
}

void
pmap_copy_page(paddr_t src, paddr_t dst)
{
	const size_t line_size = curcpu()->ci_ci.dcache_line_size;
	vaddr_t src_va = pmap_md_map_poolpage(src, NBPG);
	vaddr_t dst_va = pmap_md_map_poolpage(dst, NBPG);
	const vaddr_t end = src_va + PAGE_SIZE;

	PMAP_COUNT(copied_pages);

	while (src_va < end) {
		__asm __volatile(
			"dcbt	%2,%0"	"\n\t"	/* touch next src cacheline */
			"dcba	0,%1"	"\n\t" 	/* don't fetch dst cacheline */
		    :: "b"(src_va), "b"(dst_va), "b"(line_size));
		for (u_int i = 0;
		     i < line_size;
		     src_va += 32, dst_va += 32, i += 32) {
			register_t tmp;
			__asm __volatile(
				"mr	%[tmp],31"	"\n\t"
				"lmw	24,0(%[src])"	"\n\t"
				"stmw	24,0(%[dst])"	"\n\t"
				"mr	31,%[tmp]"	"\n\t"
			    : [tmp] "=&r"(tmp)
			    : [src] "b"(src_va), [dst] "b"(dst_va)
			    : "r24", "r25", "r26", "r27",
			      "r28", "r29", "r30", "memory");
		}
	}
	pmap_md_unmap_poolpage(src_va, NBPG);
	pmap_md_unmap_poolpage(dst_va, NBPG);

	KASSERT(!VM_PAGEMD_EXECPAGE_P(VM_PAGE_TO_MD(PHYS_TO_VM_PAGE(dst))));
}

void
pmap_md_init(void)
{

	/* nothing for now */
}

bool
pmap_md_io_vaddr_p(vaddr_t va)
{
	return va >= pmap_limits.avail_end
	    && !(VM_MIN_KERNEL_ADDRESS <= va && va < VM_MAX_KERNEL_ADDRESS);
}

bool
pmap_md_tlb_check_entry(void *ctx, vaddr_t va, tlb_asid_t asid, pt_entry_t pte)
{
	pmap_t pm = ctx;
	struct pmap_asid_info * const pai = PMAP_PAI(pm, curcpu()->ci_tlb_info);

	if (asid != pai->pai_asid)
		return true;

	const pt_entry_t * const ptep = pmap_pte_lookup(pm, va);
	KASSERT(ptep != NULL);
	pt_entry_t xpte = *ptep;
	xpte &= ~((xpte & (PTE_UNSYNCED|PTE_UNMODIFIED)) << 1);
	xpte ^= xpte & (PTE_UNSYNCED|PTE_UNMODIFIED|PTE_WIRED);

	KASSERTMSG(pte == xpte,
	    "pm=%p va=%#"PRIxVADDR" asid=%u: TLB pte (%#x) != real pte (%#x/%#x)",
	    pm, va, asid, pte, xpte, *ptep);

	return true;
}

#ifdef MULTIPROCESSOR
void
pmap_md_tlb_info_attach(struct pmap_tlb_info *ti, struct cpu_info *ci)
{
	/* nothing */
}
#endif /* MULTIPROCESSOR */
