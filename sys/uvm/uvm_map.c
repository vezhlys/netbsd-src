/*	$NetBSD: uvm_map.c,v 1.427 2025/04/27 17:40:55 riastradh Exp $	*/

/*
 * Copyright (c) 1997 Charles D. Cranor and Washington University.
 * Copyright (c) 1991, 1993, The Regents of the University of California.
 *
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * The Mach Operating System project at Carnegie-Mellon University.
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
 *	@(#)vm_map.c    8.3 (Berkeley) 1/12/94
 * from: Id: uvm_map.c,v 1.1.2.27 1998/02/07 01:16:54 chs Exp
 *
 *
 * Copyright (c) 1987, 1990 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

/*
 * uvm_map.c: uvm map operations
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: uvm_map.c,v 1.427 2025/04/27 17:40:55 riastradh Exp $");

#include "opt_ddb.h"
#include "opt_pax.h"
#include "opt_uvmhist.h"
#include "opt_uvm.h"
#include "opt_sysv.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/pool.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/pax.h>
#include <sys/vnode.h>
#include <sys/filedesc.h>
#include <sys/lockdebug.h>
#include <sys/atomic.h>
#include <sys/sysctl.h>
#ifndef __USER_VA0_IS_SAFE
#include <sys/kauth.h>
#include "opt_user_va0_disable_default.h"
#endif

#include <sys/shm.h>

#include <uvm/uvm.h>
#include <uvm/uvm_readahead.h>

#if defined(DDB) || defined(DEBUGPRINT)
#include <uvm/uvm_ddb.h>
#endif

#ifdef UVMHIST
#ifndef UVMHIST_MAPHIST_SIZE
#define UVMHIST_MAPHIST_SIZE 100
#endif
static struct kern_history_ent maphistbuf[UVMHIST_MAPHIST_SIZE];
UVMHIST_DEFINE(maphist) = UVMHIST_INITIALIZER(maphist, maphistbuf);
#endif

#if !defined(UVMMAP_COUNTERS)

#define	UVMMAP_EVCNT_DEFINE(name)	/* nothing */
#define UVMMAP_EVCNT_INCR(ev)		/* nothing */
#define UVMMAP_EVCNT_DECR(ev)		/* nothing */

#else /* defined(UVMMAP_NOCOUNTERS) */

#include <sys/evcnt.h>
#define	UVMMAP_EVCNT_DEFINE(name) \
struct evcnt uvmmap_evcnt_##name = EVCNT_INITIALIZER(EVCNT_TYPE_MISC, NULL, \
    "uvmmap", #name); \
EVCNT_ATTACH_STATIC(uvmmap_evcnt_##name);
#define	UVMMAP_EVCNT_INCR(ev)		uvmmap_evcnt_##ev.ev_count++
#define	UVMMAP_EVCNT_DECR(ev)		uvmmap_evcnt_##ev.ev_count--

#endif /* defined(UVMMAP_NOCOUNTERS) */

UVMMAP_EVCNT_DEFINE(ubackmerge)
UVMMAP_EVCNT_DEFINE(uforwmerge)
UVMMAP_EVCNT_DEFINE(ubimerge)
UVMMAP_EVCNT_DEFINE(unomerge)
UVMMAP_EVCNT_DEFINE(kbackmerge)
UVMMAP_EVCNT_DEFINE(kforwmerge)
UVMMAP_EVCNT_DEFINE(kbimerge)
UVMMAP_EVCNT_DEFINE(knomerge)
UVMMAP_EVCNT_DEFINE(map_call)
UVMMAP_EVCNT_DEFINE(mlk_call)
UVMMAP_EVCNT_DEFINE(mlk_hint)
UVMMAP_EVCNT_DEFINE(mlk_tree)
UVMMAP_EVCNT_DEFINE(mlk_treeloop)

const char vmmapbsy[] = "vmmapbsy";

/*
 * cache for dynamically-allocated map entries.
 */

static struct pool_cache uvm_map_entry_cache;

#ifdef PMAP_GROWKERNEL
/*
 * This global represents the end of the kernel virtual address
 * space.  If we want to exceed this, we must grow the kernel
 * virtual address space dynamically.
 *
 * Note, this variable is locked by kernel_map's lock.
 */
vaddr_t uvm_maxkaddr;
#endif

#ifndef __USER_VA0_IS_SAFE
#ifndef __USER_VA0_DISABLE_DEFAULT
#define __USER_VA0_DISABLE_DEFAULT 1
#endif
#ifdef USER_VA0_DISABLE_DEFAULT /* kernel config option overrides */
#undef __USER_VA0_DISABLE_DEFAULT
#define __USER_VA0_DISABLE_DEFAULT USER_VA0_DISABLE_DEFAULT
#endif
int user_va0_disable = __USER_VA0_DISABLE_DEFAULT;
#endif

/*
 * macros
 */

/*
 * uvm_map_align_va: round down or up virtual address
 */
static __inline void
uvm_map_align_va(vaddr_t *vap, vsize_t align, int topdown)
{

	KASSERT(powerof2(align));

	if (align != 0 && (*vap & (align - 1)) != 0) {
		if (topdown)
			*vap = rounddown2(*vap, align);
		else
			*vap = roundup2(*vap, align);
	}
}

/*
 * UVM_ET_ISCOMPATIBLE: check some requirements for map entry merging
 */
extern struct vm_map *pager_map;

#define	UVM_ET_ISCOMPATIBLE(ent, type, uobj, meflags, \
    prot, maxprot, inh, adv, wire) \
	((ent)->etype == (type) && \
	(((ent)->flags ^ (meflags)) & (UVM_MAP_NOMERGE)) == 0 && \
	(ent)->object.uvm_obj == (uobj) && \
	(ent)->protection == (prot) && \
	(ent)->max_protection == (maxprot) && \
	(ent)->inheritance == (inh) && \
	(ent)->advice == (adv) && \
	(ent)->wired_count == (wire))

/*
 * uvm_map_entry_link: insert entry into a map
 *
 * => map must be locked
 */
#define uvm_map_entry_link(map, after_where, entry) do { \
	uvm_mapent_check(entry); \
	(map)->nentries++; \
	(entry)->prev = (after_where); \
	(entry)->next = (after_where)->next; \
	(entry)->prev->next = (entry); \
	(entry)->next->prev = (entry); \
	uvm_rb_insert((map), (entry)); \
} while (/*CONSTCOND*/ 0)

/*
 * uvm_map_entry_unlink: remove entry from a map
 *
 * => map must be locked
 */
#define uvm_map_entry_unlink(map, entry) do { \
	KASSERT((entry) != (map)->first_free); \
	KASSERT((entry) != (map)->hint); \
	uvm_mapent_check(entry); \
	(map)->nentries--; \
	(entry)->next->prev = (entry)->prev; \
	(entry)->prev->next = (entry)->next; \
	uvm_rb_remove((map), (entry)); \
} while (/*CONSTCOND*/ 0)

/*
 * SAVE_HINT: saves the specified entry as the hint for future lookups.
 *
 * => map need not be locked.
 */
#define SAVE_HINT(map, check, value) do { \
	if ((map)->hint == (check)) \
		(map)->hint = (value); \
} while (/*CONSTCOND*/ 0)

/*
 * clear_hints: ensure that hints don't point to the entry.
 *
 * => map must be write-locked.
 */
static void
clear_hints(struct vm_map *map, struct vm_map_entry *ent)
{

	SAVE_HINT(map, ent, ent->prev);
	if (map->first_free == ent) {
		map->first_free = ent->prev;
	}
}

/*
 * VM_MAP_RANGE_CHECK: check and correct range
 *
 * => map must at least be read locked
 */

#define VM_MAP_RANGE_CHECK(map, start, end) do { \
	if (start < vm_map_min(map))		\
		start = vm_map_min(map);	\
	if (end > vm_map_max(map))		\
		end = vm_map_max(map);		\
	if (start > end)			\
		start = end;			\
} while (/*CONSTCOND*/ 0)

/*
 * local prototypes
 */

static struct vm_map_entry *
		uvm_mapent_alloc(struct vm_map *, int);
static void	uvm_mapent_copy(struct vm_map_entry *, struct vm_map_entry *);
static void	uvm_mapent_free(struct vm_map_entry *);
#if defined(DEBUG)
static void	_uvm_mapent_check(const struct vm_map_entry *, int);
#define	uvm_mapent_check(map)	_uvm_mapent_check(map, __LINE__)
#else /* defined(DEBUG) */
#define	uvm_mapent_check(e)	/* nothing */
#endif /* defined(DEBUG) */

static void	uvm_map_entry_unwire(struct vm_map *, struct vm_map_entry *);
static void	uvm_map_reference_amap(struct vm_map_entry *, int);
static int	uvm_map_space_avail(vaddr_t *, vsize_t, voff_t, vsize_t, int,
		    int, struct vm_map_entry *);
static void	uvm_map_unreference_amap(struct vm_map_entry *, int);

int _uvm_map_sanity(struct vm_map *);
int _uvm_tree_sanity(struct vm_map *);
static vsize_t uvm_rb_maxgap(const struct vm_map_entry *);

/*
 * Tree iteration.  We violate the rbtree(9) abstraction for various
 * things here.  Entries are ascending left to right, so, provided the
 * child entry in question exists:
 *
 *	LEFT_ENTRY(entry)->end <= entry->start
 *	entry->end <= RIGHT_ENTRY(entry)->start
 */
__CTASSERT(offsetof(struct vm_map_entry, rb_node) == 0);
#define	ROOT_ENTRY(map)							      \
	((struct vm_map_entry *)(map)->rb_tree.rbt_root)
#define	LEFT_ENTRY(entry)						      \
	((struct vm_map_entry *)(entry)->rb_node.rb_left)
#define	RIGHT_ENTRY(entry)						      \
	((struct vm_map_entry *)(entry)->rb_node.rb_right)
#define	PARENT_ENTRY(map, entry)					      \
	(ROOT_ENTRY(map) == (entry)					      \
	    ? NULL : (struct vm_map_entry *)RB_FATHER(&(entry)->rb_node))

/*
 * These get filled in if/when SYSVSHM shared memory code is loaded
 *
 * We do this with function pointers rather the #ifdef SYSVSHM so the
 * SYSVSHM code can be loaded and unloaded
 */
void (*uvm_shmexit)(struct vmspace *) = NULL;
void (*uvm_shmfork)(struct vmspace *, struct vmspace *) = NULL;

static int
uvm_map_compare_nodes(void *ctx, const void *nparent, const void *nkey)
{
	const struct vm_map_entry *eparent = nparent;
	const struct vm_map_entry *ekey = nkey;

	KASSERT(eparent->start < ekey->start || eparent->start >= ekey->end);
	KASSERT(ekey->start < eparent->start || ekey->start >= eparent->end);

	if (eparent->start < ekey->start)
		return -1;
	if (eparent->end >= ekey->start)
		return 1;
	return 0;
}

static int
uvm_map_compare_key(void *ctx, const void *nparent, const void *vkey)
{
	const struct vm_map_entry *eparent = nparent;
	const vaddr_t va = *(const vaddr_t *) vkey;

	if (eparent->start < va)
		return -1;
	if (eparent->end >= va)
		return 1;
	return 0;
}

static const rb_tree_ops_t uvm_map_tree_ops = {
	.rbto_compare_nodes = uvm_map_compare_nodes,
	.rbto_compare_key = uvm_map_compare_key,
	.rbto_node_offset = offsetof(struct vm_map_entry, rb_node),
	.rbto_context = NULL
};

/*
 * uvm_rb_gap: return the gap size between our entry and next entry.
 */
static inline vsize_t
uvm_rb_gap(const struct vm_map_entry *entry)
{

	KASSERT(entry->next != NULL);
	return entry->next->start - entry->end;
}

static vsize_t
uvm_rb_maxgap(const struct vm_map_entry *entry)
{
	struct vm_map_entry *child;
	vsize_t maxgap = entry->gap;

	/*
	 * We need maxgap to be the largest gap of us or any of our
	 * descendents.  Since each of our children's maxgap is the
	 * cached value of their largest gap of themselves or their
	 * descendents, we can just use that value and avoid recursing
	 * down the tree to calculate it.
	 */
	if ((child = LEFT_ENTRY(entry)) != NULL && maxgap < child->maxgap)
		maxgap = child->maxgap;

	if ((child = RIGHT_ENTRY(entry)) != NULL && maxgap < child->maxgap)
		maxgap = child->maxgap;

	return maxgap;
}

static void
uvm_rb_fixup(struct vm_map *map, struct vm_map_entry *entry)
{
	struct vm_map_entry *parent;

	KASSERT(entry->gap == uvm_rb_gap(entry));
	entry->maxgap = uvm_rb_maxgap(entry);

	while ((parent = PARENT_ENTRY(map, entry)) != NULL) {
		struct vm_map_entry *brother;
		vsize_t maxgap = parent->gap;
		unsigned int which;

		KDASSERT(parent->gap == uvm_rb_gap(parent));
		if (maxgap < entry->maxgap)
			maxgap = entry->maxgap;
		/*
		 * Since we work towards the root, we know entry's maxgap
		 * value is OK, but its brothers may now be out-of-date due
		 * to rebalancing.  So refresh it.
		 */
		which = RB_POSITION(&entry->rb_node) ^ RB_DIR_OTHER;
		brother = (struct vm_map_entry *)parent->rb_node.rb_nodes[which];
		if (brother != NULL) {
			KDASSERT(brother->gap == uvm_rb_gap(brother));
			brother->maxgap = uvm_rb_maxgap(brother);
			if (maxgap < brother->maxgap)
				maxgap = brother->maxgap;
		}

		parent->maxgap = maxgap;
		entry = parent;
	}
}

static void
uvm_rb_insert(struct vm_map *map, struct vm_map_entry *entry)
{
	struct vm_map_entry *ret __diagused;

	entry->gap = entry->maxgap = uvm_rb_gap(entry);
	if (entry->prev != &map->header)
		entry->prev->gap = uvm_rb_gap(entry->prev);

	ret = rb_tree_insert_node(&map->rb_tree, entry);
	KASSERTMSG(ret == entry,
	    "uvm_rb_insert: map %p: duplicate entry %p", map, ret);

	/*
	 * If the previous entry is not our immediate left child, then it's an
	 * ancestor and will be fixed up on the way to the root.  We don't
	 * have to check entry->prev against &map->header since &map->header
	 * will never be in the tree.
	 */
	uvm_rb_fixup(map,
	    LEFT_ENTRY(entry) == entry->prev ? entry->prev : entry);
}

static void
uvm_rb_remove(struct vm_map *map, struct vm_map_entry *entry)
{
	struct vm_map_entry *prev_parent = NULL, *next_parent = NULL;

	/*
	 * If we are removing an interior node, then an adjacent node will
	 * be used to replace its position in the tree.  Therefore we will
	 * need to fixup the tree starting at the parent of the replacement
	 * node.  So record their parents for later use.
	 */
	if (entry->prev != &map->header)
		prev_parent = PARENT_ENTRY(map, entry->prev);
	if (entry->next != &map->header)
		next_parent = PARENT_ENTRY(map, entry->next);

	rb_tree_remove_node(&map->rb_tree, entry);

	/*
	 * If the previous node has a new parent, fixup the tree starting
	 * at the previous node's old parent.
	 */
	if (entry->prev != &map->header) {
		/*
		 * Update the previous entry's gap due to our absence.
		 */
		entry->prev->gap = uvm_rb_gap(entry->prev);
		uvm_rb_fixup(map, entry->prev);
		if (prev_parent != NULL
		    && prev_parent != entry
		    && prev_parent != PARENT_ENTRY(map, entry->prev))
			uvm_rb_fixup(map, prev_parent);
	}

	/*
	 * If the next node has a new parent, fixup the tree starting
	 * at the next node's old parent.
	 */
	if (entry->next != &map->header) {
		uvm_rb_fixup(map, entry->next);
		if (next_parent != NULL
		    && next_parent != entry
		    && next_parent != PARENT_ENTRY(map, entry->next))
			uvm_rb_fixup(map, next_parent);
	}
}

#if defined(DEBUG)
int uvm_debug_check_map = 0;
int uvm_debug_check_rbtree = 0;
#define uvm_map_check(map, name) \
	_uvm_map_check((map), (name), __FILE__, __LINE__)
static void
_uvm_map_check(struct vm_map *map, const char *name,
    const char *file, int line)
{

	if ((uvm_debug_check_map && _uvm_map_sanity(map)) ||
	    (uvm_debug_check_rbtree && _uvm_tree_sanity(map))) {
		panic("uvm_map_check failed: \"%s\" map=%p (%s:%d)",
		    name, map, file, line);
	}
}
#else /* defined(DEBUG) */
#define uvm_map_check(map, name)	/* nothing */
#endif /* defined(DEBUG) */

#if defined(DEBUG) || defined(DDB)
int
_uvm_map_sanity(struct vm_map *map)
{
	bool first_free_found = false;
	bool hint_found = false;
	const struct vm_map_entry *e;
	struct vm_map_entry *hint = map->hint;

	e = &map->header;
	for (;;) {
		if (map->first_free == e) {
			first_free_found = true;
		} else if (!first_free_found && e->next->start > e->end) {
			printf("first_free %p should be %p\n",
			    map->first_free, e);
			return -1;
		}
		if (hint == e) {
			hint_found = true;
		}

		e = e->next;
		if (e == &map->header) {
			break;
		}
	}
	if (!first_free_found) {
		printf("stale first_free\n");
		return -1;
	}
	if (!hint_found) {
		printf("stale hint\n");
		return -1;
	}
	return 0;
}

int
_uvm_tree_sanity(struct vm_map *map)
{
	struct vm_map_entry *tmp, *trtmp;
	int n = 0, i = 1;

	for (tmp = map->header.next; tmp != &map->header; tmp = tmp->next) {
		if (tmp->gap != uvm_rb_gap(tmp)) {
			printf("%d/%d gap %#lx != %#lx %s\n",
			    n + 1, map->nentries,
			    (ulong)tmp->gap, (ulong)uvm_rb_gap(tmp),
			    tmp->next == &map->header ? "(last)" : "");
			goto error;
		}
		/*
		 * If any entries are out of order, tmp->gap will be unsigned
		 * and will likely exceed the size of the map.
		 */
		if (tmp->gap >= vm_map_max(map) - vm_map_min(map)) {
			printf("too large gap %zu\n", (size_t)tmp->gap);
			goto error;
		}
		n++;
	}

	if (n != map->nentries) {
		printf("nentries: %d vs %d\n", n, map->nentries);
		goto error;
	}

	trtmp = NULL;
	for (tmp = map->header.next; tmp != &map->header; tmp = tmp->next) {
		if (tmp->maxgap != uvm_rb_maxgap(tmp)) {
			printf("maxgap %#lx != %#lx\n",
			    (ulong)tmp->maxgap,
			    (ulong)uvm_rb_maxgap(tmp));
			goto error;
		}
		if (trtmp != NULL && trtmp->start >= tmp->start) {
			printf("corrupt: 0x%"PRIxVADDR"x >= 0x%"PRIxVADDR"x\n",
			    trtmp->start, tmp->start);
			goto error;
		}

		trtmp = tmp;
	}

	for (tmp = map->header.next; tmp != &map->header;
	    tmp = tmp->next, i++) {
		trtmp = rb_tree_iterate(&map->rb_tree, tmp, RB_DIR_LEFT);
		if (trtmp == NULL)
			trtmp = &map->header;
		if (tmp->prev != trtmp) {
			printf("lookup: %d: %p->prev=%p: %p\n",
			    i, tmp, tmp->prev, trtmp);
			goto error;
		}
		trtmp = rb_tree_iterate(&map->rb_tree, tmp, RB_DIR_RIGHT);
		if (trtmp == NULL)
			trtmp = &map->header;
		if (tmp->next != trtmp) {
			printf("lookup: %d: %p->next=%p: %p\n",
			    i, tmp, tmp->next, trtmp);
			goto error;
		}
		trtmp = rb_tree_find_node(&map->rb_tree, &tmp->start);
		if (trtmp != tmp) {
			printf("lookup: %d: %p - %p: %p\n", i, tmp, trtmp,
			    PARENT_ENTRY(map, tmp));
			goto error;
		}
	}

	return (0);
 error:
	return (-1);
}
#endif /* defined(DEBUG) || defined(DDB) */

/*
 * vm_map_lock: acquire an exclusive (write) lock on a map.
 *
 * => The locking protocol provides for guaranteed upgrade from shared ->
 *    exclusive by whichever thread currently has the map marked busy.
 *    See "LOCKING PROTOCOL NOTES" in uvm_map.h.  This is horrible; among
 *    other problems, it defeats any fairness guarantees provided by RW
 *    locks.
 */

void
vm_map_lock(struct vm_map *map)
{

	for (;;) {
		rw_enter(&map->lock, RW_WRITER);
		if (map->busy == NULL || map->busy == curlwp) {
			break;
		}
		mutex_enter(&map->misc_lock);
		rw_exit(&map->lock);
		if (map->busy != NULL) {
			cv_wait(&map->cv, &map->misc_lock);
		}
		mutex_exit(&map->misc_lock);
	}
	map->timestamp++;
}

/*
 * vm_map_lock_try: try to lock a map, failing if it is already locked.
 */

bool
vm_map_lock_try(struct vm_map *map)
{

	if (!rw_tryenter(&map->lock, RW_WRITER)) {
		return false;
	}
	if (map->busy != NULL) {
		rw_exit(&map->lock);
		return false;
	}
	map->timestamp++;
	return true;
}

/*
 * vm_map_unlock: release an exclusive lock on a map.
 */

void
vm_map_unlock(struct vm_map *map)
{

	KASSERT(rw_write_held(&map->lock));
	KASSERT(map->busy == NULL || map->busy == curlwp);
	rw_exit(&map->lock);
}

/*
 * vm_map_unbusy: mark the map as unbusy, and wake any waiters that
 *     want an exclusive lock.
 */

void
vm_map_unbusy(struct vm_map *map)
{

	KASSERT(map->busy == curlwp);

	/*
	 * Safe to clear 'busy' and 'waiters' with only a read lock held:
	 *
	 * o they can only be set with a write lock held
	 * o writers are blocked out with a read or write hold
	 * o at any time, only one thread owns the set of values
	 */
	mutex_enter(&map->misc_lock);
	map->busy = NULL;
	cv_broadcast(&map->cv);
	mutex_exit(&map->misc_lock);
}

/*
 * vm_map_lock_read: acquire a shared (read) lock on a map.
 */

void
vm_map_lock_read(struct vm_map *map)
{

	rw_enter(&map->lock, RW_READER);
}

/*
 * vm_map_unlock_read: release a shared lock on a map.
 */

void
vm_map_unlock_read(struct vm_map *map)
{

	rw_exit(&map->lock);
}

/*
 * vm_map_busy: mark a map as busy.
 *
 * => the caller must hold the map write locked
 */

void
vm_map_busy(struct vm_map *map)
{

	KASSERT(rw_write_held(&map->lock));
	KASSERT(map->busy == NULL);

	map->busy = curlwp;
}

/*
 * vm_map_locked_p: return true if the map is write locked.
 *
 * => only for debug purposes like KASSERTs.
 * => should not be used to verify that a map is not locked.
 */

bool
vm_map_locked_p(struct vm_map *map)
{

	return rw_write_held(&map->lock);
}

/*
 * uvm_mapent_alloc: allocate a map entry
 */

static struct vm_map_entry *
uvm_mapent_alloc(struct vm_map *map, int flags)
{
	struct vm_map_entry *me;
	int pflags = (flags & UVM_FLAG_NOWAIT) ? PR_NOWAIT : PR_WAITOK;
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	me = pool_cache_get(&uvm_map_entry_cache, pflags);
	if (__predict_false(me == NULL)) {
		return NULL;
	}
	me->flags = 0;

	UVMHIST_LOG(maphist, "<- new entry=%#jx [kentry=%jd]", (uintptr_t)me,
	    (map == kernel_map), 0, 0);
	return me;
}

/*
 * uvm_mapent_free: free map entry
 */

static void
uvm_mapent_free(struct vm_map_entry *me)
{
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"<- freeing map entry=%#jx [flags=%#jx]",
		(uintptr_t)me, me->flags, 0, 0);
	pool_cache_put(&uvm_map_entry_cache, me);
}

/*
 * uvm_mapent_copy: copy a map entry, preserving flags
 */

static inline void
uvm_mapent_copy(struct vm_map_entry *src, struct vm_map_entry *dst)
{

	memcpy(dst, src, sizeof(*dst));
	dst->flags = 0;
}

#if defined(DEBUG)
static void
_uvm_mapent_check(const struct vm_map_entry *entry, int line)
{

	if (entry->start >= entry->end) {
		goto bad;
	}
	if (UVM_ET_ISOBJ(entry)) {
		if (entry->object.uvm_obj == NULL) {
			goto bad;
		}
	} else if (UVM_ET_ISSUBMAP(entry)) {
		if (entry->object.sub_map == NULL) {
			goto bad;
		}
	} else {
		if (entry->object.uvm_obj != NULL ||
		    entry->object.sub_map != NULL) {
			goto bad;
		}
	}
	if (!UVM_ET_ISOBJ(entry)) {
		if (entry->offset != 0) {
			goto bad;
		}
	}

	return;

bad:
	panic("%s: bad entry %p, line %d", __func__, entry, line);
}
#endif /* defined(DEBUG) */

/*
 * uvm_map_entry_unwire: unwire a map entry
 *
 * => map should be locked by caller
 */

static inline void
uvm_map_entry_unwire(struct vm_map *map, struct vm_map_entry *entry)
{

	entry->wired_count = 0;
	uvm_fault_unwire_locked(map, entry->start, entry->end);
}


/*
 * wrapper for calling amap_ref()
 */
static inline void
uvm_map_reference_amap(struct vm_map_entry *entry, int flags)
{

	amap_ref(entry->aref.ar_amap, entry->aref.ar_pageoff,
	    (entry->end - entry->start) >> PAGE_SHIFT, flags);
}


/*
 * wrapper for calling amap_unref()
 */
static inline void
uvm_map_unreference_amap(struct vm_map_entry *entry, int flags)
{

	amap_unref(entry->aref.ar_amap, entry->aref.ar_pageoff,
	    (entry->end - entry->start) >> PAGE_SHIFT, flags);
}


/*
 * uvm_map_init: init mapping system at boot time.
 */

void
uvm_map_init(void)
{
	/*
	 * first, init logging system.
	 */

	UVMHIST_FUNC(__func__);
	UVMHIST_LINK_STATIC(maphist);
	UVMHIST_LINK_STATIC(pdhist);
	UVMHIST_CALLED(maphist);
	UVMHIST_LOG(maphist,"<starting uvm map system>", 0, 0, 0, 0);

	/*
	 * initialize the global lock for kernel map entry.
	 */

	mutex_init(&uvm_kentry_lock, MUTEX_DRIVER, IPL_VM);
}

/*
 * uvm_map_init_caches: init mapping system caches.
 */
void
uvm_map_init_caches(void)
{
	/*
	 * initialize caches.
	 */

	pool_cache_bootstrap(&uvm_map_entry_cache, sizeof(struct vm_map_entry),
	    coherency_unit, 0, PR_LARGECACHE, "vmmpepl", NULL, IPL_NONE, NULL,
	    NULL, NULL);
}

/*
 * clippers
 */

/*
 * uvm_mapent_splitadj: adjust map entries for splitting, after uvm_mapent_copy.
 */

static void
uvm_mapent_splitadj(struct vm_map_entry *entry1, struct vm_map_entry *entry2,
    vaddr_t splitat)
{
	vaddr_t adj;

	KASSERT(entry1->start < splitat);
	KASSERT(splitat < entry1->end);

	adj = splitat - entry1->start;
	entry1->end = entry2->start = splitat;

	if (entry1->aref.ar_amap) {
		amap_splitref(&entry1->aref, &entry2->aref, adj);
	}
	if (UVM_ET_ISSUBMAP(entry1)) {
		/* ... unlikely to happen, but play it safe */
		 uvm_map_reference(entry1->object.sub_map);
	} else if (UVM_ET_ISOBJ(entry1)) {
		KASSERT(entry1->object.uvm_obj != NULL); /* suppress coverity */
		entry2->offset += adj;
		if (entry1->object.uvm_obj->pgops &&
		    entry1->object.uvm_obj->pgops->pgo_reference)
			entry1->object.uvm_obj->pgops->pgo_reference(
			    entry1->object.uvm_obj);
	}
}

/*
 * uvm_map_clip_start: ensure that the entry begins at or after
 *	the starting address, if it doesn't we split the entry.
 *
 * => caller should use UVM_MAP_CLIP_START macro rather than calling
 *    this directly
 * => map must be locked by caller
 */

void
uvm_map_clip_start(struct vm_map *map, struct vm_map_entry *entry,
    vaddr_t start)
{
	struct vm_map_entry *new_entry;

	/* uvm_map_simplify_entry(map, entry); */ /* XXX */

	uvm_map_check(map, "clip_start entry");
	uvm_mapent_check(entry);

	/*
	 * Split off the front portion.  note that we must insert the new
	 * entry BEFORE this one, so that this entry has the specified
	 * starting address.
	 */
	new_entry = uvm_mapent_alloc(map, 0);
	uvm_mapent_copy(entry, new_entry); /* entry -> new_entry */
	uvm_mapent_splitadj(new_entry, entry, start);
	uvm_map_entry_link(map, entry->prev, new_entry);

	uvm_map_check(map, "clip_start leave");
}

/*
 * uvm_map_clip_end: ensure that the entry ends at or before
 *	the ending address, if it does't we split the reference
 *
 * => caller should use UVM_MAP_CLIP_END macro rather than calling
 *    this directly
 * => map must be locked by caller
 */

void
uvm_map_clip_end(struct vm_map *map, struct vm_map_entry *entry, vaddr_t end)
{
	struct vm_map_entry *new_entry;

	uvm_map_check(map, "clip_end entry");
	uvm_mapent_check(entry);

	/*
	 *	Create a new entry and insert it
	 *	AFTER the specified entry
	 */
	new_entry = uvm_mapent_alloc(map, 0);
	uvm_mapent_copy(entry, new_entry); /* entry -> new_entry */
	uvm_mapent_splitadj(entry, new_entry, end);
	uvm_map_entry_link(map, entry, new_entry);

	uvm_map_check(map, "clip_end leave");
}

/*
 *   M A P   -   m a i n   e n t r y   p o i n t
 */
/*
 * uvm_map: establish a valid mapping in a map
 *
 * => assume startp is page aligned.
 * => assume size is a multiple of PAGE_SIZE.
 * => assume sys_mmap provides enough of a "hint" to have us skip
 *	over text/data/bss area.
 * => map must be unlocked (we will lock it)
 * => <uobj,uoffset> value meanings (4 cases):
 *	 [1] <NULL,uoffset>		== uoffset is a hint for PMAP_PREFER
 *	 [2] <NULL,UVM_UNKNOWN_OFFSET>	== don't PMAP_PREFER
 *	 [3] <uobj,uoffset>		== normal mapping
 *	 [4] <uobj,UVM_UNKNOWN_OFFSET>	== uvm_map finds offset based on VA
 *
 *    case [4] is for kernel mappings where we don't know the offset until
 *    we've found a virtual address.   note that kernel object offsets are
 *    always relative to vm_map_min(kernel_map).
 *
 * => if `align' is non-zero, we align the virtual address to the specified
 *	alignment.
 *	this is provided as a mechanism for large pages.
 *
 * => XXXCDC: need way to map in external amap?
 */

int
uvm_map(struct vm_map *map, vaddr_t *startp /* IN/OUT */, vsize_t size,
    struct uvm_object *uobj, voff_t uoffset, vsize_t align, uvm_flag_t flags)
{
	struct uvm_map_args args;
	struct vm_map_entry *new_entry;
	int error;

	KASSERT((size & PAGE_MASK) == 0);
	KASSERT((flags & UVM_FLAG_FIXED) == 0 || align == 0);

	/*
	 * for pager_map, allocate the new entry first to avoid sleeping
	 * for memory while we have the map locked.
	 */

	new_entry = NULL;
	if (map == pager_map) {
		new_entry = uvm_mapent_alloc(map, (flags & UVM_FLAG_NOWAIT));
		if (__predict_false(new_entry == NULL))
			return ENOMEM;
	}
	if (map == pager_map)
		flags |= UVM_FLAG_NOMERGE;

	error = uvm_map_prepare(map, *startp, size, uobj, uoffset, align,
	    flags, &args);
	if (!error) {
		error = uvm_map_enter(map, &args, new_entry);
		*startp = args.uma_start;
	} else if (new_entry) {
		uvm_mapent_free(new_entry);
	}

#if defined(DEBUG)
	if (!error && VM_MAP_IS_KERNEL(map) && (flags & UVM_FLAG_NOWAIT) == 0) {
		uvm_km_check_empty(map, *startp, *startp + size);
	}
#endif /* defined(DEBUG) */

	return error;
}

/*
 * uvm_map_prepare:
 *
 * called with map unlocked.
 * on success, returns the map locked.
 */

int
uvm_map_prepare(struct vm_map *map, vaddr_t start, vsize_t size,
    struct uvm_object *uobj, voff_t uoffset, vsize_t align, uvm_flag_t flags,
    struct uvm_map_args *args)
{
	struct vm_map_entry *prev_entry;
	vm_prot_t prot = UVM_PROTECTION(flags);
	vm_prot_t maxprot = UVM_MAXPROTECTION(flags);

	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist, "(map=%#jx, start=%#jx, size=%jx, flags=%#jx)",
	    (uintptr_t)map, start, size, flags);
	UVMHIST_LOG(maphist, "  uobj/offset %#jx/%jd", (uintptr_t)uobj,
	    uoffset,0,0);

	/*
	 * detect a popular device driver bug.
	 */

	KASSERT(doing_shutdown || curlwp != NULL);

	/*
	 * zero-sized mapping doesn't make any sense.
	 */
	KASSERT(size > 0);

	KASSERT((~flags & (UVM_FLAG_NOWAIT | UVM_FLAG_WAITVA)) != 0);

	uvm_map_check(map, "map entry");

	/*
	 * check sanity of protection code
	 */

	if ((prot & maxprot) != prot) {
		UVMHIST_LOG(maphist, "<- prot. failure:  prot=%#jx, max=%#jx",
		prot, maxprot,0,0);
		return EACCES;
	}

	/*
	 * figure out where to put new VM range
	 */
retry:
	if (vm_map_lock_try(map) == false) {
		if ((flags & UVM_FLAG_TRYLOCK) != 0) {
			return EAGAIN;
		}
		vm_map_lock(map); /* could sleep here */
	}
	if (flags & UVM_FLAG_UNMAP) {
		KASSERT(flags & UVM_FLAG_FIXED);
		KASSERT((flags & UVM_FLAG_NOWAIT) == 0);

		/*
		 * Set prev_entry to what it will need to be after any existing
		 * entries are removed later in uvm_map_enter().
		 */

		if (uvm_map_lookup_entry(map, start, &prev_entry)) {
			if (start == prev_entry->start)
				prev_entry = prev_entry->prev;
			else
				UVM_MAP_CLIP_END(map, prev_entry, start);
			SAVE_HINT(map, map->hint, prev_entry);
		}
	} else {
		prev_entry = uvm_map_findspace(map, start, size, &start,
		    uobj, uoffset, align, flags);
	}
	if (prev_entry == NULL) {
		unsigned int timestamp;

		timestamp = map->timestamp;
		UVMHIST_LOG(maphist,"waiting va timestamp=%#jx",
			    timestamp,0,0,0);
		map->flags |= VM_MAP_WANTVA;
		vm_map_unlock(map);

		/*
		 * try to reclaim kva and wait until someone does unmap.
		 * fragile locking here, so we awaken every second to
		 * recheck the condition.
		 */

		mutex_enter(&map->misc_lock);
		while ((map->flags & VM_MAP_WANTVA) != 0 &&
		   map->timestamp == timestamp) {
			if ((flags & UVM_FLAG_WAITVA) == 0) {
				mutex_exit(&map->misc_lock);
				UVMHIST_LOG(maphist,
				    "<- uvm_map_findspace failed!", 0,0,0,0);
				return ENOMEM;
			} else {
				cv_timedwait(&map->cv, &map->misc_lock, hz);
			}
		}
		mutex_exit(&map->misc_lock);
		goto retry;
	}

#ifdef PMAP_GROWKERNEL
	/*
	 * If the kernel pmap can't map the requested space,
	 * then allocate more resources for it.
	 */
	if (map == kernel_map && uvm_maxkaddr < (start + size))
		uvm_maxkaddr = pmap_growkernel(start + size);
#endif

	UVMMAP_EVCNT_INCR(map_call);

	/*
	 * if uobj is null, then uoffset is either a VAC hint for PMAP_PREFER
	 * [typically from uvm_map_reserve] or it is UVM_UNKNOWN_OFFSET.   in
	 * either case we want to zero it  before storing it in the map entry
	 * (because it looks strange and confusing when debugging...)
	 *
	 * if uobj is not null
	 *   if uoffset is not UVM_UNKNOWN_OFFSET then we have a normal mapping
	 *      and we do not need to change uoffset.
	 *   if uoffset is UVM_UNKNOWN_OFFSET then we need to find the offset
	 *      now (based on the starting address of the map).   this case is
	 *      for kernel object mappings where we don't know the offset until
	 *      the virtual address is found (with uvm_map_findspace).   the
	 *      offset is the distance we are from the start of the map.
	 */

	if (uobj == NULL) {
		uoffset = 0;
	} else {
		if (uoffset == UVM_UNKNOWN_OFFSET) {
			KASSERT(UVM_OBJ_IS_KERN_OBJECT(uobj));
			uoffset = start - vm_map_min(kernel_map);
		}
	}

	args->uma_flags = flags;
	args->uma_prev = prev_entry;
	args->uma_start = start;
	args->uma_size = size;
	args->uma_uobj = uobj;
	args->uma_uoffset = uoffset;

	UVMHIST_LOG(maphist, "<- done!", 0,0,0,0);
	return 0;
}

/*
 * uvm_map_enter:
 *
 * called with map locked.
 * unlock the map before returning.
 */

int
uvm_map_enter(struct vm_map *map, const struct uvm_map_args *args,
    struct vm_map_entry *new_entry)
{
	struct vm_map_entry *prev_entry = args->uma_prev;
	struct vm_map_entry *dead = NULL, *dead_entries = NULL;

	const uvm_flag_t flags = args->uma_flags;
	const vm_prot_t prot = UVM_PROTECTION(flags);
	const vm_prot_t maxprot = UVM_MAXPROTECTION(flags);
	const vm_inherit_t inherit = UVM_INHERIT(flags);
	const int amapwaitflag = (flags & UVM_FLAG_NOWAIT) ?
	    AMAP_EXTEND_NOWAIT : 0;
	const int advice = UVM_ADVICE(flags);

	vaddr_t start = args->uma_start;
	vsize_t size = args->uma_size;
	struct uvm_object *uobj = args->uma_uobj;
	voff_t uoffset = args->uma_uoffset;

	const int kmap = (vm_map_pmap(map) == pmap_kernel());
	int merged = 0;
	int error;
	int newetype;

	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist, "(map=%#jx, start=%#jx, size=%ju, flags=%#jx)",
	    (uintptr_t)map, start, size, flags);
	UVMHIST_LOG(maphist, "  uobj/offset %#jx/%jd", (uintptr_t)uobj,
	    uoffset,0,0);

	KASSERT(map->hint == prev_entry); /* bimerge case assumes this */
	KASSERT(vm_map_locked_p(map));
	KASSERT((flags & (UVM_FLAG_NOWAIT | UVM_FLAG_UNMAP)) !=
		(UVM_FLAG_NOWAIT | UVM_FLAG_UNMAP));

	if (uobj)
		newetype = UVM_ET_OBJ;
	else
		newetype = 0;

	if (flags & UVM_FLAG_COPYONW) {
		newetype |= UVM_ET_COPYONWRITE;
		if ((flags & UVM_FLAG_OVERLAY) == 0)
			newetype |= UVM_ET_NEEDSCOPY;
	}

	/*
	 * For mappings with unmap, remove any old entries now.  Adding the new
	 * entry cannot fail because that can only happen if UVM_FLAG_NOWAIT
	 * is set, and we do not support nowait and unmap together.
	 */

	if (flags & UVM_FLAG_UNMAP) {
		KASSERT(flags & UVM_FLAG_FIXED);
		uvm_unmap_remove(map, start, start + size, &dead_entries, 0);
#ifdef DEBUG
		struct vm_map_entry *tmp_entry __diagused;
		bool rv __diagused;

		rv = uvm_map_lookup_entry(map, start, &tmp_entry);
		KASSERT(!rv);
		KASSERTMSG(prev_entry == tmp_entry,
			   "args %p prev_entry %p tmp_entry %p",
			   args, prev_entry, tmp_entry);
#endif
		SAVE_HINT(map, map->hint, prev_entry);
	}

	/*
	 * try and insert in map by extending previous entry, if possible.
	 * XXX: we don't try and pull back the next entry.   might be useful
	 * for a stack, but we are currently allocating our stack in advance.
	 */

	if (flags & UVM_FLAG_NOMERGE)
		goto nomerge;

	if (prev_entry->end == start &&
	    prev_entry != &map->header &&
	    UVM_ET_ISCOMPATIBLE(prev_entry, newetype, uobj, 0,
	    prot, maxprot, inherit, advice, 0)) {

		if (uobj && prev_entry->offset +
		    (prev_entry->end - prev_entry->start) != uoffset)
			goto forwardmerge;

		/*
		 * can't extend a shared amap.  note: no need to lock amap to
		 * look at refs since we don't care about its exact value.
		 * if it is one (i.e. we have only reference) it will stay there
		 */

		if (prev_entry->aref.ar_amap &&
		    amap_refs(prev_entry->aref.ar_amap) != 1) {
			goto forwardmerge;
		}

		if (prev_entry->aref.ar_amap) {
			error = amap_extend(prev_entry, size,
			    amapwaitflag | AMAP_EXTEND_FORWARDS);
			if (error)
				goto nomerge;
		}

		if (kmap) {
			UVMMAP_EVCNT_INCR(kbackmerge);
		} else {
			UVMMAP_EVCNT_INCR(ubackmerge);
		}
		UVMHIST_LOG(maphist,"  starting back merge", 0, 0, 0, 0);

		/*
		 * drop our reference to uobj since we are extending a reference
		 * that we already have (the ref count can not drop to zero).
		 */

		if (uobj && uobj->pgops->pgo_detach)
			uobj->pgops->pgo_detach(uobj);

		/*
		 * Now that we've merged the entries, note that we've grown
		 * and our gap has shrunk.  Then fix the tree.
		 */
		prev_entry->end += size;
		prev_entry->gap -= size;
		uvm_rb_fixup(map, prev_entry);

		uvm_map_check(map, "map backmerged");

		UVMHIST_LOG(maphist,"<- done (via backmerge)!", 0, 0, 0, 0);
		merged++;
	}

forwardmerge:
	if (prev_entry->next->start == (start + size) &&
	    prev_entry->next != &map->header &&
	    UVM_ET_ISCOMPATIBLE(prev_entry->next, newetype, uobj, 0,
	    prot, maxprot, inherit, advice, 0)) {

		if (uobj && prev_entry->next->offset != uoffset + size)
			goto nomerge;

		/*
		 * can't extend a shared amap.  note: no need to lock amap to
		 * look at refs since we don't care about its exact value.
		 * if it is one (i.e. we have only reference) it will stay there.
		 *
		 * note that we also can't merge two amaps, so if we
		 * merged with the previous entry which has an amap,
		 * and the next entry also has an amap, we give up.
		 *
		 * Interesting cases:
		 * amap, new, amap -> give up second merge (single fwd extend)
		 * amap, new, none -> double forward extend (extend again here)
		 * none, new, amap -> double backward extend (done here)
		 * uobj, new, amap -> single backward extend (done here)
		 *
		 * XXX should we attempt to deal with someone refilling
		 * the deallocated region between two entries that are
		 * backed by the same amap (ie, arefs is 2, "prev" and
		 * "next" refer to it, and adding this allocation will
		 * close the hole, thus restoring arefs to 1 and
		 * deallocating the "next" vm_map_entry)?  -- @@@
		 */

		if (prev_entry->next->aref.ar_amap &&
		    (amap_refs(prev_entry->next->aref.ar_amap) != 1 ||
		     (merged && prev_entry->aref.ar_amap))) {
			goto nomerge;
		}

		if (merged) {
			/*
			 * Try to extend the amap of the previous entry to
			 * cover the next entry as well.  If it doesn't work
			 * just skip on, don't actually give up, since we've
			 * already completed the back merge.
			 */
			if (prev_entry->aref.ar_amap) {
				if (amap_extend(prev_entry,
				    prev_entry->next->end -
				    prev_entry->next->start,
				    amapwaitflag | AMAP_EXTEND_FORWARDS))
					goto nomerge;
			}

			/*
			 * Try to extend the amap of the *next* entry
			 * back to cover the new allocation *and* the
			 * previous entry as well (the previous merge
			 * didn't have an amap already otherwise we
			 * wouldn't be checking here for an amap).  If
			 * it doesn't work just skip on, again, don't
			 * actually give up, since we've already
			 * completed the back merge.
			 */
			else if (prev_entry->next->aref.ar_amap) {
				if (amap_extend(prev_entry->next,
				    prev_entry->end -
				    prev_entry->start,
				    amapwaitflag | AMAP_EXTEND_BACKWARDS))
					goto nomerge;
			}
		} else {
			/*
			 * Pull the next entry's amap backwards to cover this
			 * new allocation.
			 */
			if (prev_entry->next->aref.ar_amap) {
				error = amap_extend(prev_entry->next, size,
				    amapwaitflag | AMAP_EXTEND_BACKWARDS);
				if (error)
					goto nomerge;
			}
		}

		if (merged) {
			if (kmap) {
				UVMMAP_EVCNT_DECR(kbackmerge);
				UVMMAP_EVCNT_INCR(kbimerge);
			} else {
				UVMMAP_EVCNT_DECR(ubackmerge);
				UVMMAP_EVCNT_INCR(ubimerge);
			}
		} else {
			if (kmap) {
				UVMMAP_EVCNT_INCR(kforwmerge);
			} else {
				UVMMAP_EVCNT_INCR(uforwmerge);
			}
		}
		UVMHIST_LOG(maphist,"  starting forward merge", 0, 0, 0, 0);

		/*
		 * drop our reference to uobj since we are extending a reference
		 * that we already have (the ref count can not drop to zero).
		 */
		if (uobj && uobj->pgops->pgo_detach)
			uobj->pgops->pgo_detach(uobj);

		if (merged) {
			dead = prev_entry->next;
			prev_entry->end = dead->end;
			uvm_map_entry_unlink(map, dead);
			if (dead->aref.ar_amap != NULL) {
				prev_entry->aref = dead->aref;
				dead->aref.ar_amap = NULL;
			}
		} else {
			prev_entry->next->start -= size;
			if (prev_entry != &map->header) {
				prev_entry->gap -= size;
				KASSERT(prev_entry->gap == uvm_rb_gap(prev_entry));
				uvm_rb_fixup(map, prev_entry);
			}
			if (uobj)
				prev_entry->next->offset = uoffset;
		}

		uvm_map_check(map, "map forwardmerged");

		UVMHIST_LOG(maphist,"<- done forwardmerge", 0, 0, 0, 0);
		merged++;
	}

nomerge:
	if (!merged) {
		UVMHIST_LOG(maphist,"  allocating new map entry", 0, 0, 0, 0);
		if (kmap) {
			UVMMAP_EVCNT_INCR(knomerge);
		} else {
			UVMMAP_EVCNT_INCR(unomerge);
		}

		/*
		 * allocate new entry and link it in.
		 */

		if (new_entry == NULL) {
			new_entry = uvm_mapent_alloc(map,
				(flags & UVM_FLAG_NOWAIT));
			if (__predict_false(new_entry == NULL)) {
				error = ENOMEM;
				goto done;
			}
		}
		new_entry->start = start;
		new_entry->end = new_entry->start + size;
		new_entry->object.uvm_obj = uobj;
		new_entry->offset = uoffset;

		new_entry->etype = newetype;

		if (flags & UVM_FLAG_NOMERGE) {
			new_entry->flags |= UVM_MAP_NOMERGE;
		}

		new_entry->protection = prot;
		new_entry->max_protection = maxprot;
		new_entry->inheritance = inherit;
		new_entry->wired_count = 0;
		new_entry->advice = advice;
		if (flags & UVM_FLAG_OVERLAY) {

			/*
			 * to_add: for BSS we overallocate a little since we
			 * are likely to extend
			 */

			vaddr_t to_add = (flags & UVM_FLAG_AMAPPAD) ?
				UVM_AMAP_CHUNK << PAGE_SHIFT : 0;
			struct vm_amap *amap = amap_alloc(size, to_add,
			    (flags & UVM_FLAG_NOWAIT));
			if (__predict_false(amap == NULL)) {
				error = ENOMEM;
				goto done;
			}
			new_entry->aref.ar_pageoff = 0;
			new_entry->aref.ar_amap = amap;
		} else {
			new_entry->aref.ar_pageoff = 0;
			new_entry->aref.ar_amap = NULL;
		}
		uvm_map_entry_link(map, prev_entry, new_entry);

		/*
		 * Update the free space hint
		 */

		if ((map->first_free == prev_entry) &&
		    (prev_entry->end >= new_entry->start))
			map->first_free = new_entry;

		new_entry = NULL;
	}

	map->size += size;

	UVMHIST_LOG(maphist,"<- done!", 0, 0, 0, 0);

	error = 0;

done:
	vm_map_unlock(map);

	if (new_entry) {
		uvm_mapent_free(new_entry);
	}
	if (dead) {
		KDASSERT(merged);
		uvm_mapent_free(dead);
	}
	if (dead_entries)
		uvm_unmap_detach(dead_entries, 0);

	return error;
}

/*
 * uvm_map_lookup_entry_bytree: lookup an entry in tree
 *
 * => map must at least be read-locked by caller.
 *
 * => If address lies in an entry, set *entry to it and return true;
 *    then (*entry)->start <= address < (*entry)->end.

 * => If address is below all entries in map, return false and set
 *    *entry to &map->header.
 *
 * => Otherwise, return false and set *entry to the highest entry below
 *    address, so (*entry)->end <= address, and if (*entry)->next is
 *    not &map->header, address < (*entry)->next->start.
 */

static inline bool
uvm_map_lookup_entry_bytree(struct vm_map *map, vaddr_t address,
    struct vm_map_entry **entry	/* OUT */)
{
	struct vm_map_entry *prev = &map->header;
	struct vm_map_entry *cur = ROOT_ENTRY(map);

	KASSERT(rw_lock_held(&map->lock));

	while (cur) {
		KASSERT(prev == &map->header || prev->end <= address);
		KASSERT(prev == &map->header || prev->end <= cur->start);
		UVMMAP_EVCNT_INCR(mlk_treeloop);
		if (address >= cur->start) {
			if (address < cur->end) {
				*entry = cur;
				return true;
			}
			prev = cur;
			KASSERT(prev->end <= address);
			cur = RIGHT_ENTRY(cur);
			KASSERT(cur == NULL || prev->end <= cur->start);
		} else
			cur = LEFT_ENTRY(cur);
	}
	KASSERT(prev == &map->header || prev->end <= address);
	KASSERT(prev->next == &map->header || address < prev->next->start);
	*entry = prev;
	return false;
}

/*
 * uvm_map_lookup_entry: find map entry at or before an address
 *
 * => map must at least be read-locked by caller.
 *
 * => If address lies in an entry, set *entry to it and return true;
 *    then (*entry)->start <= address < (*entry)->end.

 * => If address is below all entries in map, return false and set
 *    *entry to &map->header.
 *
 * => Otherwise, return false and set *entry to the highest entry below
 *    address, so (*entry)->end <= address, and if (*entry)->next is
 *    not &map->header, address < (*entry)->next->start.
 */

bool
uvm_map_lookup_entry(struct vm_map *map, vaddr_t address,
    struct vm_map_entry **entry	/* OUT */)
{
	struct vm_map_entry *cur;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,addr=%#jx,ent=%#jx)",
	    (uintptr_t)map, address, (uintptr_t)entry, 0);

	KASSERT(rw_lock_held(&map->lock));

	/*
	 * make a quick check to see if we are already looking at
	 * the entry we want (which is usually the case).  note also
	 * that we don't need to save the hint here...  it is the
	 * same hint (unless we are at the header, in which case the
	 * hint didn't buy us anything anyway).
	 */

	cur = map->hint;
	UVMMAP_EVCNT_INCR(mlk_call);
	if (cur != &map->header &&
	    address >= cur->start && cur->end > address) {
		UVMMAP_EVCNT_INCR(mlk_hint);
		*entry = cur;
		UVMHIST_LOG(maphist,"<- got it via hint (%#jx)",
		    (uintptr_t)cur, 0, 0, 0);
		uvm_mapent_check(*entry);
		return (true);
	}
	uvm_map_check(map, __func__);

	/*
	 * lookup in the tree.
	 */

	UVMMAP_EVCNT_INCR(mlk_tree);
	if (__predict_true(uvm_map_lookup_entry_bytree(map, address, entry))) {
		SAVE_HINT(map, map->hint, *entry);
		UVMHIST_LOG(maphist,"<- search got it (%#jx)",
		    (uintptr_t)cur, 0, 0, 0);
		KDASSERT((*entry)->start <= address);
		KDASSERT(address < (*entry)->end);
		uvm_mapent_check(*entry);
		return (true);
	}

	SAVE_HINT(map, map->hint, *entry);
	UVMHIST_LOG(maphist,"<- failed!",0,0,0,0);
	KDASSERT((*entry) == &map->header || (*entry)->end <= address);
	KDASSERT((*entry)->next == &map->header ||
	    address < (*entry)->next->start);
	return (false);
}

/*
 * See if the range between start and start + length fits in the gap
 * entry->next->start and entry->end.  Returns 1 if fits, 0 if doesn't
 * fit, and -1 address wraps around.
 */
static int
uvm_map_space_avail(vaddr_t *start, vsize_t length, voff_t uoffset,
    vsize_t align, int flags, int topdown, struct vm_map_entry *entry)
{
	vaddr_t orig_start = *start;
	vaddr_t end;

#define	INVARIANTS()							      \
	KASSERTMSG((topdown						      \
		? *start <= orig_start					      \
		: *start >= orig_start),				      \
	    "[%s] *start=%"PRIxVADDR" orig_start=%"PRIxVADDR		      \
	    " length=%"PRIxVSIZE" uoffset=%#llx align=%"PRIxVSIZE	      \
	    " flags=%x entry@%p=[%"PRIxVADDR",%"PRIxVADDR")"		      \
	    " ncolors=%d colormask=%x",					      \
	    topdown ? "topdown" : "bottomup", *start, orig_start,	      \
	    length, (unsigned long long)uoffset, align,			      \
	    flags, entry, entry->start, entry->end,			      \
	    uvmexp.ncolors, uvmexp.colormask)

	INVARIANTS();

#ifdef PMAP_PREFER
	/*
	 * push start address forward as needed to avoid VAC alias problems.
	 * we only do this if a valid offset is specified.
	 */

	if (uoffset != UVM_UNKNOWN_OFFSET) {
		PMAP_PREFER(uoffset, start, length, topdown);
		INVARIANTS();
	}
#endif
	if ((flags & UVM_FLAG_COLORMATCH) != 0) {
		KASSERT(align < uvmexp.ncolors);
		if (uvmexp.ncolors > 1) {
			const u_int colormask = uvmexp.colormask;
			const u_int colorsize = colormask + 1;
			vaddr_t hint = atop(*start);
			const u_int color = hint & colormask;
			if (color != align) {
				hint -= color;	/* adjust to color boundary */
				KASSERT((hint & colormask) == 0);
				if (topdown) {
					if (align > color)
						hint -= colorsize;
				} else {
					if (align < color)
						hint += colorsize;
				}
				*start = ptoa(hint + align); /* adjust to color */
				INVARIANTS();
			}
		}
	} else {
		KASSERT(powerof2(align));
		uvm_map_align_va(start, align, topdown);
		INVARIANTS();
		/*
		 * XXX Should we PMAP_PREFER() here again?
		 * eh...i think we're okay
		 */
	}

	/*
	 * Find the end of the proposed new region.  Be sure we didn't
	 * wrap around the address; if so, we lose.  Otherwise, if the
	 * proposed new region fits before the next entry, we win.
	 *
	 * XXX Should this use vm_map_max(map) as the max?
	 */

	if (length > __type_max(vaddr_t) - *start)
		return (-1);
	end = *start + length;

	if (entry->next->start >= end && *start >= entry->end)
		return (1);

	return (0);

#undef INVARIANTS
}

static void
uvm_findspace_invariants(struct vm_map *map, vaddr_t orig_hint, vaddr_t length,
    struct uvm_object *uobj, voff_t uoffset, vsize_t align, int flags,
    vaddr_t hint, struct vm_map_entry *entry, int line)
{
	const int topdown = map->flags & VM_MAP_TOPDOWN;
	const int hint_location_ok =
		topdown ? hint <= orig_hint
			: hint >= orig_hint;

	KASSERTMSG(hint_location_ok,
	    "%s map=%p hint=%#" PRIxVADDR " %s orig_hint=%#" PRIxVADDR
	    " length=%#" PRIxVSIZE " uobj=%p uoffset=%#llx align=%" PRIxVSIZE
	    " flags=%#x entry@%p=[%" PRIxVADDR ",%" PRIxVADDR ")"
	    " entry->next@%p=[%" PRIxVADDR ",%" PRIxVADDR ")"
	    " (uvm_map_findspace line %d)",
	    topdown ? "topdown" : "bottomup",
	    map, hint, topdown ? ">" : "<", orig_hint,
	    length, uobj, (unsigned long long)uoffset, align,
	    flags, entry, entry ? entry->start : 0, entry ? entry->end : 0,
	    entry ? entry->next : NULL,
	    entry && entry->next ? entry->next->start : 0,
	    entry && entry->next ? entry->next->end : 0,
	    line);
}

/*
 * uvm_map_findspace: find "length" sized space in "map".
 *
 * => "hint" is a hint about where we want it, unless UVM_FLAG_FIXED is
 *	set in "flags" (in which case we insist on using "hint").
 * => "result" is VA returned
 * => uobj/uoffset are to be used to handle VAC alignment, if required
 * => if "align" is non-zero, we attempt to align to that value.
 * => caller must at least have read-locked map
 * => returns NULL on failure, or pointer to prev. map entry if success
 * => note this is a cross between the old vm_map_findspace and vm_map_find
 */

struct vm_map_entry *
uvm_map_findspace(struct vm_map *map, vaddr_t hint, vsize_t length,
    vaddr_t *result /* OUT */, struct uvm_object *uobj, voff_t uoffset,
    vsize_t align, int flags)
{
#define	INVARIANTS()							      \
	uvm_findspace_invariants(map, orig_hint, length, uobj, uoffset, align,\
	    flags, hint, entry, __LINE__)
	struct vm_map_entry *entry = NULL;
	struct vm_map_entry *child, *prev, *tmp;
	vaddr_t orig_hint __diagused;
	const int topdown = map->flags & VM_MAP_TOPDOWN;
	int avail;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist, "(map=%#jx, hint=%#jx, len=%ju, flags=%#jx...",
	    (uintptr_t)map, hint, length, flags);
	UVMHIST_LOG(maphist, " uobj=%#jx, uoffset=%#jx, align=%#jx)",
	    (uintptr_t)uobj, uoffset, align, 0);

	KASSERT((flags & UVM_FLAG_COLORMATCH) != 0 || powerof2(align));
	KASSERT((flags & UVM_FLAG_COLORMATCH) == 0 || align < uvmexp.ncolors);
	KASSERT((flags & UVM_FLAG_FIXED) == 0 || align == 0);

	uvm_map_check(map, "map_findspace entry");

	/*
	 * Clamp the hint to the VM map's min/max address, and remmeber
	 * the clamped original hint.  Remember the original hint,
	 * clamped to the min/max address.  If we are aligning, then we
	 * may have to try again with no alignment constraint if we
	 * fail the first time.
	 *
	 * We use the original hint to verify later that the search has
	 * been monotonic -- that is, nonincreasing or nondecreasing,
	 * according to topdown or !topdown respectively.  But the
	 * clamping is not monotonic.
	 */
	if (hint < vm_map_min(map)) {	/* check ranges ... */
		if (flags & UVM_FLAG_FIXED) {
			UVMHIST_LOG(maphist,"<- VA below map range",0,0,0,0);
			return (NULL);
		}
		hint = vm_map_min(map);
	}
	if (hint > vm_map_max(map)) {
		UVMHIST_LOG(maphist,"<- VA %#jx > range [%#jx->%#jx]",
		    hint, vm_map_min(map), vm_map_max(map), 0);
		return (NULL);
	}
	orig_hint = hint;
	INVARIANTS();

	UVMHIST_LOG(maphist,"<- VA %#jx vs range [%#jx->%#jx]",
	    hint, vm_map_min(map), vm_map_max(map), 0);

	/*
	 * hint may not be aligned properly; we need round up or down it
	 * before proceeding further.
	 */
	if ((flags & UVM_FLAG_COLORMATCH) == 0) {
		uvm_map_align_va(&hint, align, topdown);
		INVARIANTS();
	}

	UVMHIST_LOG(maphist,"<- VA %#jx vs range [%#jx->%#jx]",
	    hint, vm_map_min(map), vm_map_max(map), 0);
	/*
	 * Look for the first possible address; if there's already
	 * something at this address, we have to start after it.
	 */

	/*
	 * @@@: there are four, no, eight cases to consider.
	 *
	 * 0: found,     fixed,     bottom up -> fail
	 * 1: found,     fixed,     top down  -> fail
	 * 2: found,     not fixed, bottom up -> start after entry->end,
	 *                                       loop up
	 * 3: found,     not fixed, top down  -> start before entry->start,
	 *                                       loop down
	 * 4: not found, fixed,     bottom up -> check entry->next->start, fail
	 * 5: not found, fixed,     top down  -> check entry->next->start, fail
	 * 6: not found, not fixed, bottom up -> check entry->next->start,
	 *                                       loop up
	 * 7: not found, not fixed, top down  -> check entry->next->start,
	 *                                       loop down
	 *
	 * as you can see, it reduces to roughly five cases, and that
	 * adding top down mapping only adds one unique case (without
	 * it, there would be four cases).
	 */

	if ((flags & UVM_FLAG_FIXED) == 0 &&
	    hint == (topdown ? vm_map_max(map) : vm_map_min(map))) {
		/*
		 * The uvm_map_findspace algorithm is monotonic -- for
		 * topdown VM it starts with a high hint and returns a
		 * lower free address; for !topdown VM it starts with a
		 * low hint and returns a higher free address.  As an
		 * optimization, start with the first (highest for
		 * topdown, lowest for !topdown) free address.
		 *
		 * XXX This `optimization' probably doesn't actually do
		 * much in practice unless userland explicitly passes
		 * the VM map's minimum or maximum address, which
		 * varies from machine to machine (VM_MAX/MIN_ADDRESS,
		 * e.g. 0x7fbfdfeff000 on amd64 but 0xfffffffff000 on
		 * aarch64) and may vary according to other factors
		 * like sysctl vm.user_va0_disable.  In particular, if
		 * the user specifies 0 as a hint to mmap, then mmap
		 * will choose a default address which is usually _not_
		 * VM_MAX/MIN_ADDRESS but something else instead like
		 * VM_MAX_ADDRESS - stack size - guard page overhead,
		 * in which case this branch is never hit.
		 *
		 * In fact, this branch appears to have been broken for
		 * two decades between when topdown was introduced in
		 * ~2003 and when it was adapted to handle the topdown
		 * case without violating the monotonicity assertion in
		 * 2022.  Maybe Someone^TM should either ditch the
		 * optimization or find a better way to do it.
		 */
		entry = map->first_free;
	} else if (uvm_map_lookup_entry(map, hint, &entry)) {
		KASSERT(entry->start <= hint);
		KASSERT(hint < entry->end);
		/* "hint" address already in use ... */
		if (flags & UVM_FLAG_FIXED) {
			UVMHIST_LOG(maphist, "<- fixed & VA in use",
			    0, 0, 0, 0);
			return (NULL);
		}
		if (topdown)
			/* Start from lower gap. */
			entry = entry->prev;
	} else {
		KASSERT(entry == &map->header || entry->end <= hint);
		KASSERT(entry->next == &map->header ||
		    hint < entry->next->start);
		if (flags & UVM_FLAG_FIXED) {
			if (entry->next->start >= hint &&
			    length <= entry->next->start - hint)
				goto found;

			/* "hint" address is gap but too small */
			UVMHIST_LOG(maphist, "<- fixed mapping failed",
			    0, 0, 0, 0);
			return (NULL); /* only one shot at it ... */
		} else {
			/*
			 * See if given hint fits in this gap.
			 */
			avail = uvm_map_space_avail(&hint, length,
			    uoffset, align, flags, topdown, entry);
			INVARIANTS();
			switch (avail) {
			case 1:
				goto found;
			case -1:
				goto wraparound;
			}

			if (topdown) {
				/*
				 * Still there is a chance to fit
				 * if hint > entry->end.
				 */
			} else {
				/* Start from higher gap. */
				entry = entry->next;
				if (entry == &map->header)
					goto notfound;
				goto nextgap;
			}
		}
	}

	/*
	 * Note that all UVM_FLAGS_FIXED case is already handled.
	 */
	KDASSERT((flags & UVM_FLAG_FIXED) == 0);

	/* Try to find the space in the red-black tree */

	/* Check slot before any entry */
	if (topdown) {
		KASSERTMSG(entry->next->start >= vm_map_min(map),
		    "map=%p entry=%p entry->next=%p"
		    " entry->next->start=0x%"PRIxVADDR" min=0x%"PRIxVADDR,
		    map, entry, entry->next,
		    entry->next->start, vm_map_min(map));
		if (length > entry->next->start - vm_map_min(map))
			hint = vm_map_min(map); /* XXX goto wraparound? */
		else
			hint = MIN(orig_hint, entry->next->start - length);
		KASSERT(hint >= vm_map_min(map));
	} else {
		hint = entry->end;
	}
	INVARIANTS();
	avail = uvm_map_space_avail(&hint, length, uoffset, align, flags,
	    topdown, entry);
	INVARIANTS();
	switch (avail) {
	case 1:
		goto found;
	case -1:
		goto wraparound;
	}

nextgap:
	KDASSERT((flags & UVM_FLAG_FIXED) == 0);
	/* If there is not enough space in the whole tree, we fail */
	tmp = ROOT_ENTRY(map);
	if (tmp == NULL || tmp->maxgap < length)
		goto notfound;

	prev = NULL; /* previous candidate */

	/* Find an entry close to hint that has enough space */
	for (; tmp;) {
		KASSERT(tmp->next->start == tmp->end + tmp->gap);
		if (topdown) {
			if (tmp->next->start < hint + length &&
			    (prev == NULL || tmp->end > prev->end)) {
				if (tmp->gap >= length)
					prev = tmp;
				else if ((child = LEFT_ENTRY(tmp)) != NULL
				    && child->maxgap >= length)
					prev = tmp;
			}
		} else {
			if (tmp->end >= hint &&
			    (prev == NULL || tmp->end < prev->end)) {
				if (tmp->gap >= length)
					prev = tmp;
				else if ((child = RIGHT_ENTRY(tmp)) != NULL
				    && child->maxgap >= length)
					prev = tmp;
			}
		}
		if (tmp->next->start < hint + length)
			child = RIGHT_ENTRY(tmp);
		else if (tmp->end > hint)
			child = LEFT_ENTRY(tmp);
		else {
			if (tmp->gap >= length)
				break;
			if (topdown)
				child = LEFT_ENTRY(tmp);
			else
				child = RIGHT_ENTRY(tmp);
		}
		if (child == NULL || child->maxgap < length)
			break;
		tmp = child;
	}

	if (tmp != NULL && tmp->start < hint && hint < tmp->next->start) {
		/*
		 * Check if the entry that we found satifies the
		 * space requirement
		 */
		if (topdown) {
			if (hint > tmp->next->start - length)
				hint = tmp->next->start - length;
		} else {
			if (hint < tmp->end)
				hint = tmp->end;
		}
		INVARIANTS();
		avail = uvm_map_space_avail(&hint, length, uoffset, align,
		    flags, topdown, tmp);
		INVARIANTS();
		switch (avail) {
		case 1:
			entry = tmp;
			goto found;
		case -1:
			goto wraparound;
		}
		if (tmp->gap >= length)
			goto listsearch;
	}
	if (prev == NULL)
		goto notfound;

	if (topdown) {
		KASSERT(orig_hint >= prev->next->start - length ||
		    prev->next->start - length > prev->next->start);
		hint = prev->next->start - length;
	} else {
		KASSERT(orig_hint <= prev->end);
		hint = prev->end;
	}
	INVARIANTS();
	avail = uvm_map_space_avail(&hint, length, uoffset, align,
	    flags, topdown, prev);
	INVARIANTS();
	switch (avail) {
	case 1:
		entry = prev;
		goto found;
	case -1:
		goto wraparound;
	}
	if (prev->gap >= length)
		goto listsearch;

	if (topdown)
		tmp = LEFT_ENTRY(prev);
	else
		tmp = RIGHT_ENTRY(prev);
	for (;;) {
		KASSERT(tmp);
		KASSERTMSG(tmp->maxgap >= length,
		    "tmp->maxgap=0x%"PRIxVSIZE" length=0x%"PRIxVSIZE,
		    tmp->maxgap, length);
		if (topdown)
			child = RIGHT_ENTRY(tmp);
		else
			child = LEFT_ENTRY(tmp);
		if (child && child->maxgap >= length) {
			tmp = child;
			continue;
		}
		if (tmp->gap >= length)
			break;
		if (topdown)
			tmp = LEFT_ENTRY(tmp);
		else
			tmp = RIGHT_ENTRY(tmp);
	}

	if (topdown) {
		KASSERT(orig_hint >= tmp->next->start - length ||
		    tmp->next->start - length > tmp->next->start);
		hint = tmp->next->start - length;
	} else {
		KASSERT(orig_hint <= tmp->end);
		hint = tmp->end;
	}
	INVARIANTS();
	avail = uvm_map_space_avail(&hint, length, uoffset, align,
	    flags, topdown, tmp);
	INVARIANTS();
	switch (avail) {
	case 1:
		entry = tmp;
		goto found;
	case -1:
		goto wraparound;
	}

	/*
	 * The tree fails to find an entry because of offset or alignment
	 * restrictions.  Search the list instead.
	 */
 listsearch:
	/*
	 * Look through the rest of the map, trying to fit a new region in
	 * the gap between existing regions, or after the very last region.
	 * note: entry->end = base VA of current gap,
	 *	 entry->next->start = VA of end of current gap
	 */

	INVARIANTS();
	for (;;) {
		/* Update hint for current gap. */
		hint = topdown ? MIN(orig_hint, entry->next->start - length)
		    : entry->end;
		INVARIANTS();

		/* See if it fits. */
		avail = uvm_map_space_avail(&hint, length, uoffset, align,
		    flags, topdown, entry);
		INVARIANTS();
		switch (avail) {
		case 1:
			goto found;
		case -1:
			goto wraparound;
		}

		/* Advance to next/previous gap */
		if (topdown) {
			if (entry == &map->header) {
				UVMHIST_LOG(maphist, "<- failed (off start)",
				    0,0,0,0);
				goto notfound;
			}
			entry = entry->prev;
		} else {
			entry = entry->next;
			if (entry == &map->header) {
				UVMHIST_LOG(maphist, "<- failed (off end)",
				    0,0,0,0);
				goto notfound;
			}
		}
	}

 found:
	SAVE_HINT(map, map->hint, entry);
	*result = hint;
	UVMHIST_LOG(maphist,"<- got it!  (result=%#jx)", hint, 0,0,0);
	INVARIANTS();
	KASSERT(entry->end <= hint);
	KASSERT(hint <= entry->next->start);
	KASSERT(length <= entry->next->start - hint);
	return (entry);

 wraparound:
	UVMHIST_LOG(maphist, "<- failed (wrap around)", 0,0,0,0);

	return (NULL);

 notfound:
	UVMHIST_LOG(maphist, "<- failed (notfound)", 0,0,0,0);

	return (NULL);
#undef INVARIANTS
}

/*
 *   U N M A P   -   m a i n   h e l p e r   f u n c t i o n s
 */

/*
 * uvm_unmap_remove: remove mappings from a vm_map (from "start" up to "stop")
 *
 * => caller must check alignment and size
 * => map must be locked by caller
 * => we return a list of map entries that we've remove from the map
 *    in "entry_list"
 */

void
uvm_unmap_remove(struct vm_map *map, vaddr_t start, vaddr_t end,
    struct vm_map_entry **entry_list /* OUT */, int flags)
{
	struct vm_map_entry *entry, *first_entry, *next;
	vaddr_t len;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx, start=%#jx, end=%#jx)",
	    (uintptr_t)map, start, end, 0);
	VM_MAP_RANGE_CHECK(map, start, end);

	KASSERT(vm_map_locked_p(map));

	uvm_map_check(map, "unmap_remove entry");

	/*
	 * find first entry
	 */

	if (uvm_map_lookup_entry(map, start, &first_entry) == true) {
		/* clip and go... */
		entry = first_entry;
		UVM_MAP_CLIP_START(map, entry, start);
		/* critical!  prevents stale hint */
		SAVE_HINT(map, entry, entry->prev);
	} else {
		entry = first_entry->next;
	}

	/*
	 * save the free space hint
	 */

	if (map->first_free != &map->header && map->first_free->start >= start)
		map->first_free = entry->prev;

	/*
	 * note: we now re-use first_entry for a different task.  we remove
	 * a number of map entries from the map and save them in a linked
	 * list headed by "first_entry".  once we remove them from the map
	 * the caller should unlock the map and drop the references to the
	 * backing objects [c.f. uvm_unmap_detach].  the object is to
	 * separate unmapping from reference dropping.  why?
	 *   [1] the map has to be locked for unmapping
	 *   [2] the map need not be locked for reference dropping
	 *   [3] dropping references may trigger pager I/O, and if we hit
	 *       a pager that does synchronous I/O we may have to wait for it.
	 *   [4] we would like all waiting for I/O to occur with maps unlocked
	 *       so that we don't block other threads.
	 */

	first_entry = NULL;
	*entry_list = NULL;

	/*
	 * break up the area into map entry sized regions and unmap.  note
	 * that all mappings have to be removed before we can even consider
	 * dropping references to amaps or VM objects (otherwise we could end
	 * up with a mapping to a page on the free list which would be very bad)
	 */

	while ((entry != &map->header) && (entry->start < end)) {
		KASSERT((entry->flags & UVM_MAP_STATIC) == 0);

		UVM_MAP_CLIP_END(map, entry, end);
		next = entry->next;
		len = entry->end - entry->start;

		/*
		 * unwire before removing addresses from the pmap; otherwise
		 * unwiring will put the entries back into the pmap (XXX).
		 */

		if (VM_MAPENT_ISWIRED(entry)) {
			uvm_map_entry_unwire(map, entry);
		}
		if (flags & UVM_FLAG_VAONLY) {

			/* nothing */

		} else if ((map->flags & VM_MAP_PAGEABLE) == 0) {

			/*
			 * if the map is non-pageable, any pages mapped there
			 * must be wired and entered with pmap_kenter_pa(),
			 * and we should free any such pages immediately.
			 * this is mostly used for kmem_map.
			 */
			KASSERT(vm_map_pmap(map) == pmap_kernel());

			uvm_km_pgremove_intrsafe(map, entry->start, entry->end);
		} else if (UVM_ET_ISOBJ(entry) &&
			   UVM_OBJ_IS_KERN_OBJECT(entry->object.uvm_obj)) {
			panic("%s: kernel object %p %p\n",
			    __func__, map, entry);
		} else if (UVM_ET_ISOBJ(entry) || entry->aref.ar_amap) {
			/*
			 * remove mappings the standard way.  lock object
			 * and/or amap to ensure vm_page state does not
			 * change while in pmap_remove().
			 */

#ifdef __HAVE_UNLOCKED_PMAP /* XXX temporary */
			uvm_map_lock_entry(entry, RW_WRITER);
#else
			uvm_map_lock_entry(entry, RW_READER);
#endif
			pmap_remove(map->pmap, entry->start, entry->end);

			/*
			 * note: if map is dying, leave pmap_update() for
			 * later.  if the map is to be reused (exec) then
			 * pmap_update() will be called.  if the map is
			 * being disposed of (exit) then pmap_destroy()
			 * will be called.
			 */

			if ((map->flags & VM_MAP_DYING) == 0) {
				pmap_update(vm_map_pmap(map));
			} else {
				KASSERT(vm_map_pmap(map) != pmap_kernel());
			}

			uvm_map_unlock_entry(entry);
		}

#if defined(UVMDEBUG)
		/*
		 * check if there's remaining mapping,
		 * which is a bug in caller.
		 */

		vaddr_t va;
		for (va = entry->start; va < entry->end;
		    va += PAGE_SIZE) {
			if (pmap_extract(vm_map_pmap(map), va, NULL)) {
				panic("%s: %#"PRIxVADDR" has mapping",
				    __func__, va);
			}
		}

		if (VM_MAP_IS_KERNEL(map) && (flags & UVM_FLAG_NOWAIT) == 0) {
			uvm_km_check_empty(map, entry->start, entry->end);
		}
#endif /* defined(UVMDEBUG) */

		/*
		 * remove entry from map and put it on our list of entries
		 * that we've nuked.  then go to next entry.
		 */

		UVMHIST_LOG(maphist, "  removed map entry %#jx",
		    (uintptr_t)entry, 0, 0, 0);

		/* critical!  prevents stale hint */
		SAVE_HINT(map, entry, entry->prev);

		uvm_map_entry_unlink(map, entry);
		KASSERT(map->size >= len);
		map->size -= len;
		entry->prev = NULL;
		entry->next = first_entry;
		first_entry = entry;
		entry = next;
	}

	uvm_map_check(map, "unmap_remove leave");

	/*
	 * now we've cleaned up the map and are ready for the caller to drop
	 * references to the mapped objects.
	 */

	*entry_list = first_entry;
	UVMHIST_LOG(maphist,"<- done!", 0, 0, 0, 0);

	if (map->flags & VM_MAP_WANTVA) {
		mutex_enter(&map->misc_lock);
		map->flags &= ~VM_MAP_WANTVA;
		cv_broadcast(&map->cv);
		mutex_exit(&map->misc_lock);
	}
}

/*
 * uvm_unmap_detach: drop references in a chain of map entries
 *
 * => we will free the map entries as we traverse the list.
 */

void
uvm_unmap_detach(struct vm_map_entry *first_entry, int flags)
{
	struct vm_map_entry *next_entry;
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	while (first_entry) {
		KASSERT(!VM_MAPENT_ISWIRED(first_entry));
		UVMHIST_LOG(maphist,
		    "  detach %#jx: amap=%#jx, obj=%#jx, submap?=%jd",
		    (uintptr_t)first_entry,
		    (uintptr_t)first_entry->aref.ar_amap,
		    (uintptr_t)first_entry->object.uvm_obj,
		    UVM_ET_ISSUBMAP(first_entry));

		/*
		 * drop reference to amap, if we've got one
		 */

		if (first_entry->aref.ar_amap)
			uvm_map_unreference_amap(first_entry, flags);

		/*
		 * drop reference to our backing object, if we've got one
		 */

		KASSERT(!UVM_ET_ISSUBMAP(first_entry));
		if (UVM_ET_ISOBJ(first_entry) &&
		    first_entry->object.uvm_obj->pgops->pgo_detach) {
			(*first_entry->object.uvm_obj->pgops->pgo_detach)
				(first_entry->object.uvm_obj);
		}
		next_entry = first_entry->next;
		uvm_mapent_free(first_entry);
		first_entry = next_entry;
	}
	UVMHIST_LOG(maphist, "<- done", 0,0,0,0);
}

/*
 *   E X T R A C T I O N   F U N C T I O N S
 */

/*
 * uvm_map_reserve: reserve space in a vm_map for future use.
 *
 * => we reserve space in a map by putting a dummy map entry in the
 *    map (dummy means obj=NULL, amap=NULL, prot=VM_PROT_NONE)
 * => map should be unlocked (we will write lock it)
 * => we return true if we were able to reserve space
 * => XXXCDC: should be inline?
 */

int
uvm_map_reserve(struct vm_map *map, vsize_t size,
    vaddr_t offset	/* hint for pmap_prefer */,
    vsize_t align	/* alignment */,
    vaddr_t *raddr	/* IN:hint, OUT: reserved VA */,
    uvm_flag_t flags	/* UVM_FLAG_FIXED or UVM_FLAG_COLORMATCH or 0 */)
{
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist, "(map=%#jx, size=%#jx, offset=%#jx, addr=%#jx)",
	    (uintptr_t)map, size, offset, (uintptr_t)raddr);

	size = round_page(size);

	/*
	 * reserve some virtual space.
	 */

	if (uvm_map(map, raddr, size, NULL, offset, align,
	    UVM_MAPFLAG(UVM_PROT_NONE, UVM_PROT_NONE, UVM_INH_NONE,
	    UVM_ADV_RANDOM, UVM_FLAG_NOMERGE|flags)) != 0) {
	    UVMHIST_LOG(maphist, "<- done (no VM)", 0,0,0,0);
		return (false);
	}

	UVMHIST_LOG(maphist, "<- done (*raddr=%#jx)", *raddr,0,0,0);
	return (true);
}

/*
 * uvm_map_replace: replace a reserved (blank) area of memory with
 * real mappings.
 *
 * => caller must WRITE-LOCK the map
 * => we return true if replacement was a success
 * => we expect the newents chain to have nnewents entrys on it and
 *    we expect newents->prev to point to the last entry on the list
 * => note newents is allowed to be NULL
 */

static int
uvm_map_replace(struct vm_map *map, vaddr_t start, vaddr_t end,
    struct vm_map_entry *newents, int nnewents, vsize_t nsize,
    struct vm_map_entry **oldentryp)
{
	struct vm_map_entry *oldent, *last;

	uvm_map_check(map, "map_replace entry");

	/*
	 * first find the blank map entry at the specified address
	 */

	if (!uvm_map_lookup_entry(map, start, &oldent)) {
		return (false);
	}

	/*
	 * check to make sure we have a proper blank entry
	 */

	if (end < oldent->end) {
		UVM_MAP_CLIP_END(map, oldent, end);
	}
	if (oldent->start != start || oldent->end != end ||
	    oldent->object.uvm_obj != NULL || oldent->aref.ar_amap != NULL) {
		return (false);
	}

#ifdef DIAGNOSTIC

	/*
	 * sanity check the newents chain
	 */

	{
		struct vm_map_entry *tmpent = newents;
		int nent = 0;
		vsize_t sz = 0;
		vaddr_t cur = start;

		while (tmpent) {
			nent++;
			sz += tmpent->end - tmpent->start;
			if (tmpent->start < cur)
				panic("uvm_map_replace1");
			if (tmpent->start >= tmpent->end || tmpent->end > end) {
				panic("uvm_map_replace2: "
				    "tmpent->start=%#"PRIxVADDR
				    ", tmpent->end=%#"PRIxVADDR
				    ", end=%#"PRIxVADDR,
				    tmpent->start, tmpent->end, end);
			}
			cur = tmpent->end;
			if (tmpent->next) {
				if (tmpent->next->prev != tmpent)
					panic("uvm_map_replace3");
			} else {
				if (newents->prev != tmpent)
					panic("uvm_map_replace4");
			}
			tmpent = tmpent->next;
		}
		if (nent != nnewents)
			panic("uvm_map_replace5");
		if (sz != nsize)
			panic("uvm_map_replace6");
	}
#endif

	/*
	 * map entry is a valid blank!   replace it.   (this does all the
	 * work of map entry link/unlink...).
	 */

	if (newents) {
		last = newents->prev;

		/* critical: flush stale hints out of map */
		SAVE_HINT(map, map->hint, newents);
		if (map->first_free == oldent)
			map->first_free = last;

		last->next = oldent->next;
		last->next->prev = last;

		/* Fix RB tree */
		uvm_rb_remove(map, oldent);

		newents->prev = oldent->prev;
		newents->prev->next = newents;
		map->nentries = map->nentries + (nnewents - 1);

		/* Fixup the RB tree */
		{
			int i;
			struct vm_map_entry *tmp;

			tmp = newents;
			for (i = 0; i < nnewents && tmp; i++) {
				uvm_rb_insert(map, tmp);
				tmp = tmp->next;
			}
		}
	} else {
		/* NULL list of new entries: just remove the old one */
		clear_hints(map, oldent);
		uvm_map_entry_unlink(map, oldent);
	}
	map->size -= end - start - nsize;

	uvm_map_check(map, "map_replace leave");

	/*
	 * now we can free the old blank entry and return.
	 */

	*oldentryp = oldent;
	return (true);
}

/*
 * uvm_map_extract: extract a mapping from a map and put it somewhere
 *	(maybe removing the old mapping)
 *
 * => maps should be unlocked (we will write lock them)
 * => returns 0 on success, error code otherwise
 * => start must be page aligned
 * => len must be page sized
 * => flags:
 *      UVM_EXTRACT_REMOVE: remove mappings from srcmap
 *      UVM_EXTRACT_CONTIG: abort if unmapped area (advisory only)
 *      UVM_EXTRACT_QREF: for a temporary extraction do quick obj refs
 *      UVM_EXTRACT_FIXPROT: set prot to maxprot as we go
 *      UVM_EXTRACT_PROT_ALL: set prot to UVM_PROT_ALL as we go
 *    >>>NOTE: if you set REMOVE, you are not allowed to use CONTIG or QREF!<<<
 *    >>>NOTE: QREF's must be unmapped via the QREF path, thus should only
 *             be used from within the kernel in a kernel level map <<<
 */

int
uvm_map_extract(struct vm_map *srcmap, vaddr_t start, vsize_t len,
    struct vm_map *dstmap, vaddr_t *dstaddrp, int flags)
{
	vaddr_t dstaddr, end, newend, oldoffset, fudge, orig_fudge;
	struct vm_map_entry *chain, *endchain, *entry, *orig_entry, *newentry,
	    *deadentry, *oldentry;
	struct vm_map_entry *resentry = NULL; /* a dummy reservation entry */
	vsize_t elen __unused;
	int nchain, error, copy_ok;
	vsize_t nsize;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(srcmap=%#jx,start=%#jx, len=%#jx",
	    (uintptr_t)srcmap, start, len, 0);
	UVMHIST_LOG(maphist," ...,dstmap=%#jx, flags=%#jx)",
	    (uintptr_t)dstmap, flags, 0, 0);

	/*
	 * step 0: sanity check: start must be on a page boundary, length
	 * must be page sized.  can't ask for CONTIG/QREF if you asked for
	 * REMOVE.
	 */

	KASSERTMSG((start & PAGE_MASK) == 0, "start=0x%"PRIxVADDR, start);
	KASSERTMSG((len & PAGE_MASK) == 0, "len=0x%"PRIxVADDR, len);
	KASSERT((flags & UVM_EXTRACT_REMOVE) == 0 ||
		(flags & (UVM_EXTRACT_CONTIG|UVM_EXTRACT_QREF)) == 0);

	/*
	 * step 1: reserve space in the target map for the extracted area
	 */

	if ((flags & UVM_EXTRACT_RESERVED) == 0) {
		dstaddr = vm_map_min(dstmap);
		if (!uvm_map_reserve(dstmap, len, start,
		    atop(start) & uvmexp.colormask, &dstaddr,
		    UVM_FLAG_COLORMATCH))
			return (ENOMEM);
		KASSERT((atop(start ^ dstaddr) & uvmexp.colormask) == 0);
		*dstaddrp = dstaddr;	/* pass address back to caller */
		UVMHIST_LOG(maphist, "  dstaddr=%#jx", dstaddr,0,0,0);
	} else {
		dstaddr = *dstaddrp;
	}

	/*
	 * step 2: setup for the extraction process loop by init'ing the
	 * map entry chain, locking src map, and looking up the first useful
	 * entry in the map.
	 */

	end = start + len;
	newend = dstaddr + len;
	chain = endchain = NULL;
	nchain = 0;
	nsize = 0;
	vm_map_lock(srcmap);

	if (uvm_map_lookup_entry(srcmap, start, &entry)) {

		/* "start" is within an entry */
		if (flags & UVM_EXTRACT_QREF) {

			/*
			 * for quick references we don't clip the entry, so
			 * the entry may map space "before" the starting
			 * virtual address... this is the "fudge" factor
			 * (which can be non-zero only the first time
			 * through the "while" loop in step 3).
			 */

			fudge = start - entry->start;
		} else {

			/*
			 * normal reference: we clip the map to fit (thus
			 * fudge is zero)
			 */

			UVM_MAP_CLIP_START(srcmap, entry, start);
			SAVE_HINT(srcmap, srcmap->hint, entry->prev);
			fudge = 0;
		}
	} else {

		/* "start" is not within an entry ... skip to next entry */
		if (flags & UVM_EXTRACT_CONTIG) {
			error = EINVAL;
			goto bad;    /* definite hole here ... */
		}

		entry = entry->next;
		fudge = 0;
	}

	/* save values from srcmap for step 6 */
	orig_entry = entry;
	orig_fudge = fudge;

	/*
	 * step 3: now start looping through the map entries, extracting
	 * as we go.
	 */

	while (entry->start < end && entry != &srcmap->header) {

		/* if we are not doing a quick reference, clip it */
		if ((flags & UVM_EXTRACT_QREF) == 0)
			UVM_MAP_CLIP_END(srcmap, entry, end);

		/* clear needs_copy (allow chunking) */
		if (UVM_ET_ISNEEDSCOPY(entry)) {
			amap_copy(srcmap, entry,
			    AMAP_COPY_NOWAIT|AMAP_COPY_NOMERGE, start, end);
			if (UVM_ET_ISNEEDSCOPY(entry)) {  /* failed? */
				error = ENOMEM;
				goto bad;
			}

			/* amap_copy could clip (during chunk)!  update fudge */
			if (fudge) {
				fudge = start - entry->start;
				orig_fudge = fudge;
			}
		}

		/* calculate the offset of this from "start" */
		oldoffset = (entry->start + fudge) - start;

		/* allocate a new map entry */
		newentry = uvm_mapent_alloc(dstmap, 0);
		if (newentry == NULL) {
			error = ENOMEM;
			goto bad;
		}

		/* set up new map entry */
		newentry->next = NULL;
		newentry->prev = endchain;
		newentry->start = dstaddr + oldoffset;
		newentry->end =
		    newentry->start + (entry->end - (entry->start + fudge));
		if (newentry->end > newend || newentry->end < newentry->start)
			newentry->end = newend;
		newentry->object.uvm_obj = entry->object.uvm_obj;
		if (newentry->object.uvm_obj) {
			if (newentry->object.uvm_obj->pgops->pgo_reference)
				newentry->object.uvm_obj->pgops->
				    pgo_reference(newentry->object.uvm_obj);
			newentry->offset = entry->offset + fudge;
		} else {
			newentry->offset = 0;
		}
		newentry->etype = entry->etype;
		if (flags & UVM_EXTRACT_PROT_ALL) {
			newentry->protection = newentry->max_protection =
			    UVM_PROT_ALL;
		} else {
			newentry->protection = (flags & UVM_EXTRACT_FIXPROT) ?
			    entry->max_protection : entry->protection;
			newentry->max_protection = entry->max_protection;
		}
		newentry->inheritance = entry->inheritance;
		newentry->wired_count = 0;
		newentry->aref.ar_amap = entry->aref.ar_amap;
		if (newentry->aref.ar_amap) {
			newentry->aref.ar_pageoff =
			    entry->aref.ar_pageoff + (fudge >> PAGE_SHIFT);
			uvm_map_reference_amap(newentry, AMAP_SHARED |
			    ((flags & UVM_EXTRACT_QREF) ? AMAP_REFALL : 0));
		} else {
			newentry->aref.ar_pageoff = 0;
		}
		newentry->advice = entry->advice;
		if ((flags & UVM_EXTRACT_QREF) != 0) {
			newentry->flags |= UVM_MAP_NOMERGE;
		}

		/* now link it on the chain */
		nchain++;
		nsize += newentry->end - newentry->start;
		if (endchain == NULL) {
			chain = endchain = newentry;
		} else {
			endchain->next = newentry;
			endchain = newentry;
		}

		/* end of 'while' loop! */
		if ((flags & UVM_EXTRACT_CONTIG) && entry->end < end &&
		    (entry->next == &srcmap->header ||
		    entry->next->start != entry->end)) {
			error = EINVAL;
			goto bad;
		}
		entry = entry->next;
		fudge = 0;
	}

	/*
	 * step 4: close off chain (in format expected by uvm_map_replace)
	 */

	if (chain)
		chain->prev = endchain;

	/*
	 * step 5: attempt to lock the dest map so we can pmap_copy.
	 * note usage of copy_ok:
	 *   1 => dstmap locked, pmap_copy ok, and we "replace" here (step 5)
	 *   0 => dstmap unlocked, NO pmap_copy, and we will "replace" in step 7
	 */

	if (srcmap == dstmap || vm_map_lock_try(dstmap) == true) {
		copy_ok = 1;
		if (!uvm_map_replace(dstmap, dstaddr, dstaddr+len, chain,
		    nchain, nsize, &resentry)) {
			if (srcmap != dstmap)
				vm_map_unlock(dstmap);
			error = EIO;
			goto bad;
		}
	} else {
		copy_ok = 0;
		/* replace deferred until step 7 */
	}

	/*
	 * step 6: traverse the srcmap a second time to do the following:
	 *  - if we got a lock on the dstmap do pmap_copy
	 *  - if UVM_EXTRACT_REMOVE remove the entries
	 * we make use of orig_entry and orig_fudge (saved in step 2)
	 */

	if (copy_ok || (flags & UVM_EXTRACT_REMOVE)) {

		/* purge possible stale hints from srcmap */
		if (flags & UVM_EXTRACT_REMOVE) {
			SAVE_HINT(srcmap, srcmap->hint, orig_entry->prev);
			if (srcmap->first_free != &srcmap->header &&
			    srcmap->first_free->start >= start)
				srcmap->first_free = orig_entry->prev;
		}

		entry = orig_entry;
		fudge = orig_fudge;
		deadentry = NULL;	/* for UVM_EXTRACT_REMOVE */

		while (entry->start < end && entry != &srcmap->header) {
			if (copy_ok) {
				oldoffset = (entry->start + fudge) - start;
				elen = MIN(end, entry->end) -
				    (entry->start + fudge);
				pmap_copy(dstmap->pmap, srcmap->pmap,
				    dstaddr + oldoffset, elen,
				    entry->start + fudge);
			}

			/* we advance "entry" in the following if statement */
			if (flags & UVM_EXTRACT_REMOVE) {
#ifdef __HAVE_UNLOCKED_PMAP /* XXX temporary */
				uvm_map_lock_entry(entry, RW_WRITER);
#else
				uvm_map_lock_entry(entry, RW_READER);
#endif
				pmap_remove(srcmap->pmap, entry->start,
						entry->end);
				uvm_map_unlock_entry(entry);
				oldentry = entry;	/* save entry */
				entry = entry->next;	/* advance */
				uvm_map_entry_unlink(srcmap, oldentry);
							/* add to dead list */
				oldentry->next = deadentry;
				deadentry = oldentry;
			} else {
				entry = entry->next;		/* advance */
			}

			/* end of 'while' loop */
			fudge = 0;
		}
		pmap_update(srcmap->pmap);

		/*
		 * unlock dstmap.  we will dispose of deadentry in
		 * step 7 if needed
		 */

		if (copy_ok && srcmap != dstmap)
			vm_map_unlock(dstmap);

	} else {
		deadentry = NULL;
	}

	/*
	 * step 7: we are done with the source map, unlock.   if copy_ok
	 * is 0 then we have not replaced the dummy mapping in dstmap yet
	 * and we need to do so now.
	 */

	vm_map_unlock(srcmap);
	if ((flags & UVM_EXTRACT_REMOVE) && deadentry)
		uvm_unmap_detach(deadentry, 0);   /* dispose of old entries */

	/* now do the replacement if we didn't do it in step 5 */
	if (copy_ok == 0) {
		vm_map_lock(dstmap);
		error = uvm_map_replace(dstmap, dstaddr, dstaddr+len, chain,
		    nchain, nsize, &resentry);
		vm_map_unlock(dstmap);

		if (error == false) {
			error = EIO;
			goto bad2;
		}
	}

	if (resentry != NULL)
		uvm_mapent_free(resentry);

	return (0);

	/*
	 * bad: failure recovery
	 */
bad:
	vm_map_unlock(srcmap);
bad2:			/* src already unlocked */
	if (chain)
		uvm_unmap_detach(chain,
		    (flags & UVM_EXTRACT_QREF) ? AMAP_REFALL : 0);

	if (resentry != NULL)
		uvm_mapent_free(resentry);

	if ((flags & UVM_EXTRACT_RESERVED) == 0) {
		uvm_unmap(dstmap, dstaddr, dstaddr+len);   /* ??? */
	}
	return (error);
}

/* end of extraction functions */

/*
 * uvm_map_submap: punch down part of a map into a submap
 *
 * => only the kernel_map is allowed to be submapped
 * => the purpose of submapping is to break up the locking granularity
 *	of a larger map
 * => the range specified must have been mapped previously with a uvm_map()
 *	call [with uobj==NULL] to create a blank map entry in the main map.
 *	[And it had better still be blank!]
 * => maps which contain submaps should never be copied or forked.
 * => to remove a submap, use uvm_unmap() on the main map
 *	and then uvm_map_deallocate() the submap.
 * => main map must be unlocked.
 * => submap must have been init'd and have a zero reference count.
 *	[need not be locked as we don't actually reference it]
 */

int
uvm_map_submap(struct vm_map *map, vaddr_t start, vaddr_t end,
    struct vm_map *submap)
{
	struct vm_map_entry *entry;
	int error;

	vm_map_lock(map);
	VM_MAP_RANGE_CHECK(map, start, end);

	if (uvm_map_lookup_entry(map, start, &entry)) {
		UVM_MAP_CLIP_START(map, entry, start);
		UVM_MAP_CLIP_END(map, entry, end);	/* to be safe */
	} else {
		entry = NULL;
	}

	if (entry != NULL &&
	    entry->start == start && entry->end == end &&
	    entry->object.uvm_obj == NULL && entry->aref.ar_amap == NULL &&
	    !UVM_ET_ISCOPYONWRITE(entry) && !UVM_ET_ISNEEDSCOPY(entry)) {
		entry->etype |= UVM_ET_SUBMAP;
		entry->object.sub_map = submap;
		entry->offset = 0;
		uvm_map_reference(submap);
		error = 0;
	} else {
		error = EINVAL;
	}
	vm_map_unlock(map);

	return error;
}

/*
 * uvm_map_protect_user: change map protection on behalf of the user.
 * Enforces PAX settings as necessary.
 */
int
uvm_map_protect_user(struct lwp *l, vaddr_t start, vaddr_t end,
    vm_prot_t new_prot)
{
	int error;

	if ((error = PAX_MPROTECT_VALIDATE(l, new_prot)))
		return error;

	return uvm_map_protect(&l->l_proc->p_vmspace->vm_map, start, end,
	    new_prot, false);
}


/*
 * uvm_map_protect: change map protection
 *
 * => set_max means set max_protection.
 * => map must be unlocked.
 */

#define MASK(entry)	(UVM_ET_ISCOPYONWRITE(entry) ? \
			 ~VM_PROT_WRITE : VM_PROT_ALL)

int
uvm_map_protect(struct vm_map *map, vaddr_t start, vaddr_t end,
    vm_prot_t new_prot, bool set_max)
{
	struct vm_map_entry *current, *entry;
	int error = 0;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,start=%#jx,end=%#jx,new_prot=%#jx)",
	    (uintptr_t)map, start, end, new_prot);

	vm_map_lock(map);
	VM_MAP_RANGE_CHECK(map, start, end);
	if (uvm_map_lookup_entry(map, start, &entry)) {
		UVM_MAP_CLIP_START(map, entry, start);
	} else {
		entry = entry->next;
	}

	/*
	 * make a first pass to check for protection violations.
	 */

	current = entry;
	while ((current != &map->header) && (current->start < end)) {
		if (UVM_ET_ISSUBMAP(current)) {
			error = EINVAL;
			goto out;
		}
		if ((new_prot & current->max_protection) != new_prot) {
			error = EACCES;
			goto out;
		}
		/*
		 * Don't allow VM_PROT_EXECUTE to be set on entries that
		 * point to vnodes that are associated with a NOEXEC file
		 * system.
		 */
		if (UVM_ET_ISOBJ(current) &&
		    UVM_OBJ_IS_VNODE(current->object.uvm_obj)) {
			struct vnode *vp =
			    (struct vnode *) current->object.uvm_obj;

			if ((new_prot & VM_PROT_EXECUTE) != 0 &&
			    (vp->v_mount->mnt_flag & MNT_NOEXEC) != 0) {
				error = EACCES;
				goto out;
			}
		}

		current = current->next;
	}

	/* go back and fix up protections (no need to clip this time). */

	current = entry;
	while ((current != &map->header) && (current->start < end)) {
		vm_prot_t old_prot;

		UVM_MAP_CLIP_END(map, current, end);
		old_prot = current->protection;
		if (set_max)
			current->protection =
			    (current->max_protection = new_prot) & old_prot;
		else
			current->protection = new_prot;

		/*
		 * update physical map if necessary.  worry about copy-on-write
		 * here -- CHECK THIS XXX
		 */

		if (current->protection != old_prot) {
			/* update pmap! */
#ifdef __HAVE_UNLOCKED_PMAP /* XXX temporary */
			uvm_map_lock_entry(current, RW_WRITER);
#else
			uvm_map_lock_entry(current, RW_READER);
#endif
			pmap_protect(map->pmap, current->start, current->end,
			    current->protection & MASK(current));
			uvm_map_unlock_entry(current);

			/*
			 * If this entry points at a vnode, and the
			 * protection includes VM_PROT_EXECUTE, mark
			 * the vnode as VEXECMAP.
			 */
			if (UVM_ET_ISOBJ(current)) {
				struct uvm_object *uobj =
				    current->object.uvm_obj;

				if (UVM_OBJ_IS_VNODE(uobj) &&
				    (current->protection & VM_PROT_EXECUTE)) {
					vn_markexec((struct vnode *) uobj);
				}
			}
		}

		/*
		 * If the map is configured to lock any future mappings,
		 * wire this entry now if the old protection was VM_PROT_NONE
		 * and the new protection is not VM_PROT_NONE.
		 */

		if ((map->flags & VM_MAP_WIREFUTURE) != 0 &&
		    VM_MAPENT_ISWIRED(current) == 0 &&
		    old_prot == VM_PROT_NONE &&
		    new_prot != VM_PROT_NONE) {

			/*
			 * We must call pmap_update() here because the
			 * pmap_protect() call above might have removed some
			 * pmap entries and uvm_map_pageable() might create
			 * some new pmap entries that rely on the prior
			 * removals being completely finished.
			 */

			pmap_update(map->pmap);

			if (uvm_map_pageable(map, current->start,
			    current->end, false,
			    UVM_LK_ENTER|UVM_LK_EXIT) != 0) {

				/*
				 * If locking the entry fails, remember the
				 * error if it's the first one.  Note we
				 * still continue setting the protection in
				 * the map, but will return the error
				 * condition regardless.
				 *
				 * XXX Ignore what the actual error is,
				 * XXX just call it a resource shortage
				 * XXX so that it doesn't get confused
				 * XXX what uvm_map_protect() itself would
				 * XXX normally return.
				 */

				error = ENOMEM;
			}
		}
		current = current->next;
	}
	pmap_update(map->pmap);

 out:
	vm_map_unlock(map);

	UVMHIST_LOG(maphist, "<- done, error=%jd",error,0,0,0);
	return error;
}

#undef  MASK

/*
 * uvm_map_inherit: set inheritance code for range of addrs in map.
 *
 * => map must be unlocked
 * => note that the inherit code is used during a "fork".  see fork
 *	code for details.
 */

int
uvm_map_inherit(struct vm_map *map, vaddr_t start, vaddr_t end,
    vm_inherit_t new_inheritance)
{
	struct vm_map_entry *entry, *temp_entry;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,start=%#jx,end=%#jx,new_inh=%#jx)",
	    (uintptr_t)map, start, end, new_inheritance);

	switch (new_inheritance) {
	case MAP_INHERIT_NONE:
	case MAP_INHERIT_COPY:
	case MAP_INHERIT_SHARE:
	case MAP_INHERIT_ZERO:
		break;
	default:
		UVMHIST_LOG(maphist,"<- done (INVALID ARG)",0,0,0,0);
		return EINVAL;
	}

	vm_map_lock(map);
	VM_MAP_RANGE_CHECK(map, start, end);
	if (uvm_map_lookup_entry(map, start, &temp_entry)) {
		entry = temp_entry;
		UVM_MAP_CLIP_START(map, entry, start);
	}  else {
		entry = temp_entry->next;
	}
	while ((entry != &map->header) && (entry->start < end)) {
		UVM_MAP_CLIP_END(map, entry, end);
		entry->inheritance = new_inheritance;
		entry = entry->next;
	}
	vm_map_unlock(map);
	UVMHIST_LOG(maphist,"<- done (OK)",0,0,0,0);
	return 0;
}

/*
 * uvm_map_advice: set advice code for range of addrs in map.
 *
 * => map must be unlocked
 */

int
uvm_map_advice(struct vm_map *map, vaddr_t start, vaddr_t end, int new_advice)
{
	struct vm_map_entry *entry, *temp_entry;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,start=%#jx,end=%#jx,new_adv=%#jx)",
	    (uintptr_t)map, start, end, new_advice);

	vm_map_lock(map);
	VM_MAP_RANGE_CHECK(map, start, end);
	if (uvm_map_lookup_entry(map, start, &temp_entry)) {
		entry = temp_entry;
		UVM_MAP_CLIP_START(map, entry, start);
	} else {
		entry = temp_entry->next;
	}

	/*
	 * XXXJRT: disallow holes?
	 */

	while ((entry != &map->header) && (entry->start < end)) {
		UVM_MAP_CLIP_END(map, entry, end);

		switch (new_advice) {
		case MADV_NORMAL:
		case MADV_RANDOM:
		case MADV_SEQUENTIAL:
			/* nothing special here */
			break;

		default:
			vm_map_unlock(map);
			UVMHIST_LOG(maphist,"<- done (INVALID ARG)",0,0,0,0);
			return EINVAL;
		}
		entry->advice = new_advice;
		entry = entry->next;
	}

	vm_map_unlock(map);
	UVMHIST_LOG(maphist,"<- done (OK)",0,0,0,0);
	return 0;
}

/*
 * uvm_map_willneed: apply MADV_WILLNEED
 */

int
uvm_map_willneed(struct vm_map *map, vaddr_t start, vaddr_t end)
{
	struct vm_map_entry *entry;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,start=%#jx,end=%#jx)",
	    (uintptr_t)map, start, end, 0);

	vm_map_lock_read(map);
	VM_MAP_RANGE_CHECK(map, start, end);
	if (!uvm_map_lookup_entry(map, start, &entry)) {
		entry = entry->next;
	}
	while (entry->start < end) {
		struct vm_amap * const amap = entry->aref.ar_amap;
		struct uvm_object * const uobj = entry->object.uvm_obj;

		KASSERT(entry != &map->header);
		KASSERT(start < entry->end);
		/*
		 * For now, we handle only the easy but commonly-requested case.
		 * ie. start prefetching of backing uobj pages.
		 *
		 * XXX It might be useful to pmap_enter() the already-in-core
		 * pages by inventing a "weak" mode for uvm_fault() which would
		 * only do the PGO_LOCKED pgo_get().
		 */
		if (UVM_ET_ISOBJ(entry) && amap == NULL && uobj != NULL) {
			off_t offset;
			off_t size;

			offset = entry->offset;
			if (start < entry->start) {
				offset += entry->start - start;
			}
			size = entry->offset + (entry->end - entry->start);
			if (entry->end < end) {
				size -= end - entry->end;
			}
			uvm_readahead(uobj, offset, size);
		}
		entry = entry->next;
	}
	vm_map_unlock_read(map);
	UVMHIST_LOG(maphist,"<- done (OK)",0,0,0,0);
	return 0;
}

/*
 * uvm_map_pageable: sets the pageability of a range in a map.
 *
 * => wires map entries.  should not be used for transient page locking.
 *	for that, use uvm_fault_wire()/uvm_fault_unwire() (see uvm_vslock()).
 * => regions specified as not pageable require lock-down (wired) memory
 *	and page tables.
 * => map must never be read-locked
 * => if islocked is true, map is already write-locked
 * => we always unlock the map, since we must downgrade to a read-lock
 *	to call uvm_fault_wire()
 * => XXXCDC: check this and try and clean it up.
 */

int
uvm_map_pageable(struct vm_map *map, vaddr_t start, vaddr_t end,
    bool new_pageable, int lockflags)
{
	struct vm_map_entry *entry, *start_entry, *failed_entry;
	int rv;
#ifdef DIAGNOSTIC
	u_int timestamp_save;
#endif
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,start=%#jx,end=%#jx,new_pageable=%ju)",
	    (uintptr_t)map, start, end, new_pageable);
	KASSERT(map->flags & VM_MAP_PAGEABLE);

	if ((lockflags & UVM_LK_ENTER) == 0)
		vm_map_lock(map);
	VM_MAP_RANGE_CHECK(map, start, end);

	/*
	 * only one pageability change may take place at one time, since
	 * uvm_fault_wire assumes it will be called only once for each
	 * wiring/unwiring.  therefore, we have to make sure we're actually
	 * changing the pageability for the entire region.  we do so before
	 * making any changes.
	 */

	if (uvm_map_lookup_entry(map, start, &start_entry) == false) {
		if ((lockflags & UVM_LK_EXIT) == 0)
			vm_map_unlock(map);

		UVMHIST_LOG(maphist,"<- done (fault)",0,0,0,0);
		return EFAULT;
	}
	entry = start_entry;

	if (start == end) {		/* nothing required */
		if ((lockflags & UVM_LK_EXIT) == 0)
			vm_map_unlock(map);

		UVMHIST_LOG(maphist,"<- done (nothing)",0,0,0,0);
		return 0;
	}

	/*
	 * handle wiring and unwiring separately.
	 */

	if (new_pageable) {		/* unwire */
		UVM_MAP_CLIP_START(map, entry, start);

		/*
		 * unwiring.  first ensure that the range to be unwired is
		 * really wired down and that there are no holes.
		 */

		while ((entry != &map->header) && (entry->start < end)) {
			if (entry->wired_count == 0 ||
			    (entry->end < end &&
			     (entry->next == &map->header ||
			      entry->next->start > entry->end))) {
				if ((lockflags & UVM_LK_EXIT) == 0)
					vm_map_unlock(map);
				UVMHIST_LOG(maphist, "<- done (INVAL)",0,0,0,0);
				return EINVAL;
			}
			entry = entry->next;
		}

		/*
		 * POSIX 1003.1b - a single munlock call unlocks a region,
		 * regardless of the number of mlock calls made on that
		 * region.
		 */

		entry = start_entry;
		while ((entry != &map->header) && (entry->start < end)) {
			UVM_MAP_CLIP_END(map, entry, end);
			if (VM_MAPENT_ISWIRED(entry))
				uvm_map_entry_unwire(map, entry);
			entry = entry->next;
		}
		if ((lockflags & UVM_LK_EXIT) == 0)
			vm_map_unlock(map);
		UVMHIST_LOG(maphist,"<- done (OK UNWIRE)",0,0,0,0);
		return 0;
	}

	/*
	 * wire case: in two passes [XXXCDC: ugly block of code here]
	 *
	 * 1: holding the write lock, we create any anonymous maps that need
	 *    to be created.  then we clip each map entry to the region to
	 *    be wired and increment its wiring count.
	 *
	 * 2: we downgrade to a read lock, and call uvm_fault_wire to fault
	 *    in the pages for any newly wired area (wired_count == 1).
	 *
	 *    downgrading to a read lock for uvm_fault_wire avoids a possible
	 *    deadlock with another thread that may have faulted on one of
	 *    the pages to be wired (it would mark the page busy, blocking
	 *    us, then in turn block on the map lock that we hold).  because
	 *    of problems in the recursive lock package, we cannot upgrade
	 *    to a write lock in vm_map_lookup.  thus, any actions that
	 *    require the write lock must be done beforehand.  because we
	 *    keep the read lock on the map, the copy-on-write status of the
	 *    entries we modify here cannot change.
	 */

	while ((entry != &map->header) && (entry->start < end)) {
		if (VM_MAPENT_ISWIRED(entry) == 0) { /* not already wired? */

			/*
			 * perform actions of vm_map_lookup that need the
			 * write lock on the map: create an anonymous map
			 * for a copy-on-write region, or an anonymous map
			 * for a zero-fill region.  (XXXCDC: submap case
			 * ok?)
			 */

			if (!UVM_ET_ISSUBMAP(entry)) {  /* not submap */
				if (UVM_ET_ISNEEDSCOPY(entry) &&
				    ((entry->max_protection & VM_PROT_WRITE) ||
				     (entry->object.uvm_obj == NULL))) {
					amap_copy(map, entry, 0, start, end);
					/* XXXCDC: wait OK? */
				}
			}
		}
		UVM_MAP_CLIP_START(map, entry, start);
		UVM_MAP_CLIP_END(map, entry, end);
		entry->wired_count++;

		/*
		 * Check for holes
		 */

		if (entry->protection == VM_PROT_NONE ||
		    (entry->end < end &&
		     (entry->next == &map->header ||
		      entry->next->start > entry->end))) {

			/*
			 * found one.  amap creation actions do not need to
			 * be undone, but the wired counts need to be restored.
			 */

			while (entry != &map->header && entry->end > start) {
				entry->wired_count--;
				entry = entry->prev;
			}
			if ((lockflags & UVM_LK_EXIT) == 0)
				vm_map_unlock(map);
			UVMHIST_LOG(maphist,"<- done (INVALID WIRE)",0,0,0,0);
			return EINVAL;
		}
		entry = entry->next;
	}

	/*
	 * Pass 2.
	 */

#ifdef DIAGNOSTIC
	timestamp_save = map->timestamp;
#endif
	vm_map_busy(map);
	vm_map_unlock(map);

	rv = 0;
	entry = start_entry;
	while (entry != &map->header && entry->start < end) {
		if (entry->wired_count == 1) {
			rv = uvm_fault_wire(map, entry->start, entry->end,
			    entry->max_protection, 1);
			if (rv) {

				/*
				 * wiring failed.  break out of the loop.
				 * we'll clean up the map below, once we
				 * have a write lock again.
				 */

				break;
			}
		}
		entry = entry->next;
	}

	if (rv) {	/* failed? */

		/*
		 * Get back to an exclusive (write) lock.
		 */

		vm_map_lock(map);
		vm_map_unbusy(map);

#ifdef DIAGNOSTIC
		if (timestamp_save + 1 != map->timestamp)
			panic("uvm_map_pageable: stale map");
#endif

		/*
		 * first drop the wiring count on all the entries
		 * which haven't actually been wired yet.
		 */

		failed_entry = entry;
		while (entry != &map->header && entry->start < end) {
			entry->wired_count--;
			entry = entry->next;
		}

		/*
		 * now, unwire all the entries that were successfully
		 * wired above.
		 */

		entry = start_entry;
		while (entry != failed_entry) {
			entry->wired_count--;
			if (VM_MAPENT_ISWIRED(entry) == 0)
				uvm_map_entry_unwire(map, entry);
			entry = entry->next;
		}
		if ((lockflags & UVM_LK_EXIT) == 0)
			vm_map_unlock(map);
		UVMHIST_LOG(maphist, "<- done (RV=%jd)", rv,0,0,0);
		return (rv);
	}

	if ((lockflags & UVM_LK_EXIT) == 0) {
		vm_map_unbusy(map);
	} else {

		/*
		 * Get back to an exclusive (write) lock.
		 */

		vm_map_lock(map);
		vm_map_unbusy(map);
	}

	UVMHIST_LOG(maphist,"<- done (OK WIRE)",0,0,0,0);
	return 0;
}

/*
 * uvm_map_pageable_all: special case of uvm_map_pageable - affects
 * all mapped regions.
 *
 * => map must not be locked.
 * => if no flags are specified, all regions are unwired.
 * => XXXJRT: has some of the same problems as uvm_map_pageable() above.
 */

int
uvm_map_pageable_all(struct vm_map *map, int flags, vsize_t limit)
{
	struct vm_map_entry *entry, *failed_entry;
	vsize_t size;
	int rv;
#ifdef DIAGNOSTIC
	u_int timestamp_save;
#endif
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,flags=%#jx)", (uintptr_t)map, flags,
	    0, 0);

	KASSERT(map->flags & VM_MAP_PAGEABLE);

	vm_map_lock(map);

	/*
	 * handle wiring and unwiring separately.
	 */

	if (flags == 0) {			/* unwire */

		/*
		 * POSIX 1003.1b -- munlockall unlocks all regions,
		 * regardless of how many times mlockall has been called.
		 */

		for (entry = map->header.next; entry != &map->header;
		     entry = entry->next) {
			if (VM_MAPENT_ISWIRED(entry))
				uvm_map_entry_unwire(map, entry);
		}
		map->flags &= ~VM_MAP_WIREFUTURE;
		vm_map_unlock(map);
		UVMHIST_LOG(maphist,"<- done (OK UNWIRE)",0,0,0,0);
		return 0;
	}

	if (flags & MCL_FUTURE) {

		/*
		 * must wire all future mappings; remember this.
		 */

		map->flags |= VM_MAP_WIREFUTURE;
	}

	if ((flags & MCL_CURRENT) == 0) {

		/*
		 * no more work to do!
		 */

		UVMHIST_LOG(maphist,"<- done (OK no wire)",0,0,0,0);
		vm_map_unlock(map);
		return 0;
	}

	/*
	 * wire case: in three passes [XXXCDC: ugly block of code here]
	 *
	 * 1: holding the write lock, count all pages mapped by non-wired
	 *    entries.  if this would cause us to go over our limit, we fail.
	 *
	 * 2: still holding the write lock, we create any anonymous maps that
	 *    need to be created.  then we increment its wiring count.
	 *
	 * 3: we downgrade to a read lock, and call uvm_fault_wire to fault
	 *    in the pages for any newly wired area (wired_count == 1).
	 *
	 *    downgrading to a read lock for uvm_fault_wire avoids a possible
	 *    deadlock with another thread that may have faulted on one of
	 *    the pages to be wired (it would mark the page busy, blocking
	 *    us, then in turn block on the map lock that we hold).  because
	 *    of problems in the recursive lock package, we cannot upgrade
	 *    to a write lock in vm_map_lookup.  thus, any actions that
	 *    require the write lock must be done beforehand.  because we
	 *    keep the read lock on the map, the copy-on-write status of the
	 *    entries we modify here cannot change.
	 */

	for (size = 0, entry = map->header.next; entry != &map->header;
	     entry = entry->next) {
		if (entry->protection != VM_PROT_NONE &&
		    VM_MAPENT_ISWIRED(entry) == 0) { /* not already wired? */
			size += entry->end - entry->start;
		}
	}

	if (atop(size) + uvmexp.wired > uvmexp.wiredmax) {
		vm_map_unlock(map);
		return ENOMEM;
	}

	if (limit != 0 &&
	    (size + ptoa(pmap_wired_count(vm_map_pmap(map))) > limit)) {
		vm_map_unlock(map);
		return ENOMEM;
	}

	/*
	 * Pass 2.
	 */

	for (entry = map->header.next; entry != &map->header;
	     entry = entry->next) {
		if (entry->protection == VM_PROT_NONE)
			continue;
		if (VM_MAPENT_ISWIRED(entry) == 0) { /* not already wired? */

			/*
			 * perform actions of vm_map_lookup that need the
			 * write lock on the map: create an anonymous map
			 * for a copy-on-write region, or an anonymous map
			 * for a zero-fill region.  (XXXCDC: submap case
			 * ok?)
			 */

			if (!UVM_ET_ISSUBMAP(entry)) {	/* not submap */
				if (UVM_ET_ISNEEDSCOPY(entry) &&
				    ((entry->max_protection & VM_PROT_WRITE) ||
				     (entry->object.uvm_obj == NULL))) {
					amap_copy(map, entry, 0, entry->start,
					    entry->end);
					/* XXXCDC: wait OK? */
				}
			}
		}
		entry->wired_count++;
	}

	/*
	 * Pass 3.
	 */

#ifdef DIAGNOSTIC
	timestamp_save = map->timestamp;
#endif
	vm_map_busy(map);
	vm_map_unlock(map);

	rv = 0;
	for (entry = map->header.next; entry != &map->header;
	     entry = entry->next) {
		if (entry->wired_count == 1) {
			rv = uvm_fault_wire(map, entry->start, entry->end,
			    entry->max_protection, 1);
			if (rv) {

				/*
				 * wiring failed.  break out of the loop.
				 * we'll clean up the map below, once we
				 * have a write lock again.
				 */

				break;
			}
		}
	}

	if (rv) {

		/*
		 * Get back an exclusive (write) lock.
		 */

		vm_map_lock(map);
		vm_map_unbusy(map);

#ifdef DIAGNOSTIC
		if (timestamp_save + 1 != map->timestamp)
			panic("uvm_map_pageable_all: stale map");
#endif

		/*
		 * first drop the wiring count on all the entries
		 * which haven't actually been wired yet.
		 *
		 * Skip VM_PROT_NONE entries like we did above.
		 */

		failed_entry = entry;
		for (/* nothing */; entry != &map->header;
		     entry = entry->next) {
			if (entry->protection == VM_PROT_NONE)
				continue;
			entry->wired_count--;
		}

		/*
		 * now, unwire all the entries that were successfully
		 * wired above.
		 *
		 * Skip VM_PROT_NONE entries like we did above.
		 */

		for (entry = map->header.next; entry != failed_entry;
		     entry = entry->next) {
			if (entry->protection == VM_PROT_NONE)
				continue;
			entry->wired_count--;
			if (VM_MAPENT_ISWIRED(entry))
				uvm_map_entry_unwire(map, entry);
		}
		vm_map_unlock(map);
		UVMHIST_LOG(maphist,"<- done (RV=%jd)", rv,0,0,0);
		return (rv);
	}

	vm_map_unbusy(map);

	UVMHIST_LOG(maphist,"<- done (OK WIRE)",0,0,0,0);
	return 0;
}

/*
 * uvm_map_clean: clean out a map range
 *
 * => valid flags:
 *   if (flags & PGO_CLEANIT): dirty pages are cleaned first
 *   if (flags & PGO_SYNCIO): dirty pages are written synchronously
 *   if (flags & PGO_DEACTIVATE): any cached pages are deactivated after clean
 *   if (flags & PGO_FREE): any cached pages are freed after clean
 * => returns an error if any part of the specified range isn't mapped
 * => never a need to flush amap layer since the anonymous memory has
 *	no permanent home, but may deactivate pages there
 * => called from sys_msync() and sys_madvise()
 * => caller must not have map locked
 */

int
uvm_map_clean(struct vm_map *map, vaddr_t start, vaddr_t end, int flags)
{
	struct vm_map_entry *current, *entry;
	struct uvm_object *uobj;
	struct vm_amap *amap;
	struct vm_anon *anon;
	struct vm_page *pg;
	vaddr_t offset;
	vsize_t size;
	voff_t uoff;
	int error, refs;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(map=%#jx,start=%#jx,end=%#jx,flags=%#jx)",
	    (uintptr_t)map, start, end, flags);

	KASSERT((flags & (PGO_FREE|PGO_DEACTIVATE)) !=
		(PGO_FREE|PGO_DEACTIVATE));

	vm_map_lock(map);
	VM_MAP_RANGE_CHECK(map, start, end);
	if (!uvm_map_lookup_entry(map, start, &entry)) {
		vm_map_unlock(map);
		return EFAULT;
	}

	/*
	 * Make a first pass to check for holes and wiring problems.
	 */

	for (current = entry; current->start < end; current = current->next) {
		if (UVM_ET_ISSUBMAP(current)) {
			vm_map_unlock(map);
			return EINVAL;
		}
		if ((flags & PGO_FREE) != 0 && VM_MAPENT_ISWIRED(entry)) {
			vm_map_unlock(map);
			return EBUSY;
		}
		if (end <= current->end) {
			break;
		}
		if (current->end != current->next->start) {
			vm_map_unlock(map);
			return EFAULT;
		}
	}

	vm_map_busy(map);
	vm_map_unlock(map);
	error = 0;
	for (current = entry; start < end; current = current->next) {
		amap = current->aref.ar_amap;	/* upper layer */
		uobj = current->object.uvm_obj;	/* lower layer */
		KASSERT(start >= current->start);

		/*
		 * No amap cleaning necessary if:
		 *
		 *	(1) There's no amap.
		 *
		 *	(2) We're not deactivating or freeing pages.
		 */

		if (amap == NULL || (flags & (PGO_DEACTIVATE|PGO_FREE)) == 0)
			goto flush_object;

		offset = start - current->start;
		size = MIN(end, current->end) - start;

		amap_lock(amap, RW_WRITER);
		for ( ; size != 0; size -= PAGE_SIZE, offset += PAGE_SIZE) {
			anon = amap_lookup(&current->aref, offset);
			if (anon == NULL)
				continue;

			KASSERT(anon->an_lock == amap->am_lock);
			pg = anon->an_page;
			if (pg == NULL) {
				continue;
			}
			if (pg->flags & PG_BUSY) {
				continue;
			}

			switch (flags & (PGO_CLEANIT|PGO_FREE|PGO_DEACTIVATE)) {

			/*
			 * In these first 3 cases, we just deactivate the page.
			 */

			case PGO_CLEANIT|PGO_FREE:
			case PGO_CLEANIT|PGO_DEACTIVATE:
			case PGO_DEACTIVATE:
 deactivate_it:
				/*
				 * skip the page if it's loaned or wired,
				 * since it shouldn't be on a paging queue
				 * at all in these cases.
				 */

				if (pg->loan_count != 0 ||
				    pg->wire_count != 0) {
					continue;
				}
				KASSERT(pg->uanon == anon);
				uvm_pagelock(pg);
				uvm_pagedeactivate(pg);
				uvm_pageunlock(pg);
				continue;

			case PGO_FREE:

				/*
				 * If there are multiple references to
				 * the amap, just deactivate the page.
				 */

				if (amap_refs(amap) > 1)
					goto deactivate_it;

				/* skip the page if it's wired */
				if (pg->wire_count != 0) {
					continue;
				}
				amap_unadd(&current->aref, offset);
				refs = --anon->an_ref;
				if (refs == 0) {
					uvm_anfree(anon);
				}
				continue;
			}
		}
		amap_unlock(amap);

 flush_object:
		/*
		 * flush pages if we've got a valid backing object.
		 * note that we must always clean object pages before
		 * freeing them since otherwise we could reveal stale
		 * data from files.
		 */

		uoff = current->offset + (start - current->start);
		size = MIN(end, current->end) - start;
		if (uobj != NULL) {
			rw_enter(uobj->vmobjlock, RW_WRITER);
			if (uobj->pgops->pgo_put != NULL)
				error = (uobj->pgops->pgo_put)(uobj, uoff,
				    uoff + size, flags | PGO_CLEANIT);
			else
				error = 0;
		}
		start += size;
	}
	vm_map_unbusy(map);
	return error;
}


/*
 * uvm_map_checkprot: check protection in map
 *
 * => must allow specified protection in a fully allocated region.
 * => map must be read or write locked by caller.
 */

bool
uvm_map_checkprot(struct vm_map *map, vaddr_t start, vaddr_t end,
    vm_prot_t protection)
{
	struct vm_map_entry *entry;
	struct vm_map_entry *tmp_entry;

	if (!uvm_map_lookup_entry(map, start, &tmp_entry)) {
		return (false);
	}
	entry = tmp_entry;
	while (start < end) {
		if (entry == &map->header) {
			return (false);
		}

		/*
		 * no holes allowed
		 */

		if (start < entry->start) {
			return (false);
		}

		/*
		 * check protection associated with entry
		 */

		if ((entry->protection & protection) != protection) {
			return (false);
		}
		start = entry->end;
		entry = entry->next;
	}
	return (true);
}

/*
 * uvmspace_alloc: allocate a vmspace structure.
 *
 * - structure includes vm_map and pmap
 * - XXX: no locking on this structure
 * - refcnt set to 1, rest must be init'd by caller
 */
struct vmspace *
uvmspace_alloc(vaddr_t vmin, vaddr_t vmax, bool topdown)
{
	struct vmspace *vm;
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	vm = kmem_alloc(sizeof(*vm), KM_SLEEP);
	uvmspace_init(vm, NULL, vmin, vmax, topdown);
	UVMHIST_LOG(maphist,"<- done (vm=%#jx)", (uintptr_t)vm, 0, 0, 0);
	return (vm);
}

/*
 * uvmspace_init: initialize a vmspace structure.
 *
 * - XXX: no locking on this structure
 * - refcnt set to 1, rest must be init'd by caller
 */
void
uvmspace_init(struct vmspace *vm, struct pmap *pmap, vaddr_t vmin,
    vaddr_t vmax, bool topdown)
{
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist, "(vm=%#jx, pmap=%#jx, vmin=%#jx, vmax=%#jx",
	    (uintptr_t)vm, (uintptr_t)pmap, vmin, vmax);
	UVMHIST_LOG(maphist, "   topdown=%ju)", topdown, 0, 0, 0);

	memset(vm, 0, sizeof(*vm));
	uvm_map_setup(&vm->vm_map, vmin, vmax, VM_MAP_PAGEABLE
	    | (topdown ? VM_MAP_TOPDOWN : 0)
	    );
	if (pmap)
		pmap_reference(pmap);
	else
		pmap = pmap_create();
	vm->vm_map.pmap = pmap;
	vm->vm_refcnt = 1;
	UVMHIST_LOG(maphist,"<- done",0,0,0,0);
}

/*
 * uvmspace_share: share a vmspace between two processes
 *
 * - used for vfork, threads(?)
 */

void
uvmspace_share(struct proc *p1, struct proc *p2)
{

	uvmspace_addref(p1->p_vmspace);
	p2->p_vmspace = p1->p_vmspace;
}

#if 0

/*
 * uvmspace_unshare: ensure that process "p" has its own, unshared, vmspace
 *
 * - XXX: no locking on vmspace
 */

void
uvmspace_unshare(struct lwp *l)
{
	struct proc *p = l->l_proc;
	struct vmspace *nvm, *ovm = p->p_vmspace;

	if (ovm->vm_refcnt == 1)
		/* nothing to do: vmspace isn't shared in the first place */
		return;

	/* make a new vmspace, still holding old one */
	nvm = uvmspace_fork(ovm);

	kpreempt_disable();
	pmap_deactivate(l);		/* unbind old vmspace */
	p->p_vmspace = nvm;
	pmap_activate(l);		/* switch to new vmspace */
	kpreempt_enable();

	uvmspace_free(ovm);		/* drop reference to old vmspace */
}

#endif

/*
 * uvmspace_exec: the process wants to exec a new program
 */

void
uvmspace_exec(struct lwp *l, vaddr_t start, vaddr_t end, bool topdown)
{
	struct proc *p = l->l_proc;
	struct vmspace *nvm, *ovm = p->p_vmspace;
	struct vm_map *map;
	int flags;

	KASSERT(ovm != NULL);
#ifdef __HAVE_CPU_VMSPACE_EXEC
	cpu_vmspace_exec(l, start, end);
#endif

	/*
	 * If p is the only process using the vmspace, we can safely
	 * recycle it for the program that is being exec'd, rather than
	 * allocate a new vmspace -- but we have to make sure it's
	 * empty first.
	 */
	map = &ovm->vm_map;
	if (ovm->vm_refcnt == 1 && map->nentries != 0) {
		/*
		 * SYSV SHM semantics require us to kill all segments on an exec
		 */
		if (uvm_shmexit && ovm->vm_shm)
			(*uvm_shmexit)(ovm);

		/*
		 * POSIX 1003.1b -- "lock future mappings" is revoked
		 * when a process execs another program image.
		 */
		map->flags &= ~VM_MAP_WIREFUTURE;

		/*
		 * now unmap the old program.
		 *
		 * XXX set VM_MAP_DYING for the duration, so pmap_update()
		 * is not called until the pmap has been totally cleared out
		 * after pmap_remove_all(), or it can confuse some pmap
		 * implementations.  it would be nice to handle this by
		 * deferring the pmap_update() while it is known the address
		 * space is not visible to any user LWP other than curlwp,
		 * but there isn't an elegant way of inferring that right
		 * now.
		 */
		flags = pmap_remove_all(map->pmap) ? UVM_FLAG_VAONLY : 0;
		map->flags |= VM_MAP_DYING;
		uvm_unmap1(map, vm_map_min(map), vm_map_max(map), flags);
		map->flags &= ~VM_MAP_DYING;
		pmap_update(map->pmap);
		KASSERT(map->header.prev == &map->header);
		KASSERT(map->nentries == 0);
	}

	if (ovm->vm_refcnt == 1) {
		/*
		 * The vmspace is not shared and is empty (if it
		 * weren't, we would have emptied it above).
		 *
		 * Resize the map and set topdown as appropriate.
		 */
		KASSERT(map->nentries == 0);
		vm_map_setmin(map, start);
		vm_map_setmax(map, end);
		if (topdown) {
			map->flags |= VM_MAP_TOPDOWN;
		} else {
			map->flags &= ~VM_MAP_TOPDOWN;
		}
	} else {
		/*
		 * p's vmspace is being shared, so we can't reuse it for p since
		 * it is still being used for others.   allocate a new vmspace
		 * for p
		 */
		nvm = uvmspace_alloc(start, end, topdown);

		/*
		 * install new vmspace and drop our ref to the old one.
		 */
		kpreempt_disable();
		pmap_deactivate(l);
		p->p_vmspace = nvm;
		pmap_activate(l);
		kpreempt_enable();

		uvmspace_free(ovm);
	}
}

/*
 * uvmspace_addref: add a reference to a vmspace.
 */

void
uvmspace_addref(struct vmspace *vm)
{

	KASSERT((vm->vm_map.flags & VM_MAP_DYING) == 0);
	KASSERT(vm->vm_refcnt > 0);
	atomic_inc_uint(&vm->vm_refcnt);
}

/*
 * uvmspace_free: free a vmspace data structure
 */

void
uvmspace_free(struct vmspace *vm)
{
	struct vm_map_entry *dead_entries;
	struct vm_map *map = &vm->vm_map;
	int flags;

	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist,"(vm=%#jx) ref=%jd", (uintptr_t)vm,
	    vm->vm_refcnt, 0, 0);

	membar_release();
	if (atomic_dec_uint_nv(&vm->vm_refcnt) > 0)
		return;
	membar_acquire();

	/*
	 * at this point, there should be no other references to the map.
	 * delete all of the mappings, then destroy the pmap.
	 */

	map->flags |= VM_MAP_DYING;
	flags = pmap_remove_all(map->pmap) ? UVM_FLAG_VAONLY : 0;

	/* Get rid of any SYSV shared memory segments. */
	if (uvm_shmexit && vm->vm_shm != NULL)
		(*uvm_shmexit)(vm);

	if (map->nentries) {
		vm_map_lock(map);
		uvm_unmap_remove(map, vm_map_min(map), vm_map_max(map),
		    &dead_entries, flags);
		vm_map_unlock(map);
		if (dead_entries != NULL)
			uvm_unmap_detach(dead_entries, 0);
	}
	KASSERT(map->nentries == 0);
	KASSERT(map->size == 0);

	mutex_destroy(&map->misc_lock);
	rw_destroy(&map->lock);
	cv_destroy(&map->cv);
	pmap_destroy(map->pmap);
	kmem_free(vm, sizeof(*vm));
}

static struct vm_map_entry *
uvm_mapent_clone(struct vm_map *new_map, struct vm_map_entry *old_entry,
    int flags)
{
	struct vm_map_entry *new_entry;

	new_entry = uvm_mapent_alloc(new_map, 0);
	/* old_entry -> new_entry */
	uvm_mapent_copy(old_entry, new_entry);

	/* new pmap has nothing wired in it */
	new_entry->wired_count = 0;

	/*
	 * gain reference to object backing the map (can't
	 * be a submap, already checked this case).
	 */

	if (new_entry->aref.ar_amap)
		uvm_map_reference_amap(new_entry, flags);

	if (new_entry->object.uvm_obj &&
	    new_entry->object.uvm_obj->pgops->pgo_reference)
		new_entry->object.uvm_obj->pgops->pgo_reference(
			new_entry->object.uvm_obj);

	/* insert entry at end of new_map's entry list */
	uvm_map_entry_link(new_map, new_map->header.prev,
	    new_entry);

	return new_entry;
}

/*
 * share the mapping: this means we want the old and
 * new entries to share amaps and backing objects.
 */
static void
uvm_mapent_forkshared(struct vm_map *new_map, struct vm_map *old_map,
    struct vm_map_entry *old_entry)
{
	/*
	 * if the old_entry needs a new amap (due to prev fork)
	 * then we need to allocate it now so that we have
	 * something we own to share with the new_entry.   [in
	 * other words, we need to clear needs_copy]
	 */

	if (UVM_ET_ISNEEDSCOPY(old_entry)) {
		/* get our own amap, clears needs_copy */
		amap_copy(old_map, old_entry, AMAP_COPY_NOCHUNK,
		    0, 0);
		/* XXXCDC: WAITOK??? */
	}

	uvm_mapent_clone(new_map, old_entry, AMAP_SHARED);
}


static void
uvm_mapent_forkcopy(struct vm_map *new_map, struct vm_map *old_map,
    struct vm_map_entry *old_entry)
{
	struct vm_map_entry *new_entry;

	/*
	 * copy-on-write the mapping (using mmap's
	 * MAP_PRIVATE semantics)
	 *
	 * allocate new_entry, adjust reference counts.
	 * (note that new references are read-only).
	 */

	new_entry = uvm_mapent_clone(new_map, old_entry, 0);

	new_entry->etype |=
	    (UVM_ET_COPYONWRITE|UVM_ET_NEEDSCOPY);

	/*
	 * the new entry will need an amap.  it will either
	 * need to be copied from the old entry or created
	 * from scratch (if the old entry does not have an
	 * amap).  can we defer this process until later
	 * (by setting "needs_copy") or do we need to copy
	 * the amap now?
	 *
	 * we must copy the amap now if any of the following
	 * conditions hold:
	 * 1. the old entry has an amap and that amap is
	 *    being shared.  this means that the old (parent)
	 *    process is sharing the amap with another
	 *    process.  if we do not clear needs_copy here
	 *    we will end up in a situation where both the
	 *    parent and child process are referring to the
	 *    same amap with "needs_copy" set.  if the
	 *    parent write-faults, the fault routine will
	 *    clear "needs_copy" in the parent by allocating
	 *    a new amap.   this is wrong because the
	 *    parent is supposed to be sharing the old amap
	 *    and the new amap will break that.
	 *
	 * 2. if the old entry has an amap and a non-zero
	 *    wire count then we are going to have to call
	 *    amap_cow_now to avoid page faults in the
	 *    parent process.   since amap_cow_now requires
	 *    "needs_copy" to be clear we might as well
	 *    clear it here as well.
	 *
	 */

	if (old_entry->aref.ar_amap != NULL) {
		if ((amap_flags(old_entry->aref.ar_amap) & AMAP_SHARED) != 0 ||
		    VM_MAPENT_ISWIRED(old_entry)) {

			amap_copy(new_map, new_entry,
			    AMAP_COPY_NOCHUNK, 0, 0);
			/* XXXCDC: M_WAITOK ... ok? */
		}
	}

	/*
	 * if the parent's entry is wired down, then the
	 * parent process does not want page faults on
	 * access to that memory.  this means that we
	 * cannot do copy-on-write because we can't write
	 * protect the old entry.   in this case we
	 * resolve all copy-on-write faults now, using
	 * amap_cow_now.   note that we have already
	 * allocated any needed amap (above).
	 */

	if (VM_MAPENT_ISWIRED(old_entry)) {

		/*
		 * resolve all copy-on-write faults now
		 * (note that there is nothing to do if
		 * the old mapping does not have an amap).
		 */
		if (old_entry->aref.ar_amap)
			amap_cow_now(new_map, new_entry);

	} else {
		/*
		 * setup mappings to trigger copy-on-write faults
		 * we must write-protect the parent if it has
		 * an amap and it is not already "needs_copy"...
		 * if it is already "needs_copy" then the parent
		 * has already been write-protected by a previous
		 * fork operation.
		 */
		if (old_entry->aref.ar_amap &&
		    !UVM_ET_ISNEEDSCOPY(old_entry)) {
			if (old_entry->max_protection & VM_PROT_WRITE) {
#ifdef __HAVE_UNLOCKED_PMAP /* XXX temporary */
				uvm_map_lock_entry(old_entry, RW_WRITER);
#else
				uvm_map_lock_entry(old_entry, RW_READER);
#endif
				pmap_protect(old_map->pmap,
				    old_entry->start, old_entry->end,
				    old_entry->protection & ~VM_PROT_WRITE);
				uvm_map_unlock_entry(old_entry);
			}
			old_entry->etype |= UVM_ET_NEEDSCOPY;
		}
	}
}

/*
 * zero the mapping: the new entry will be zero initialized
 */
static void
uvm_mapent_forkzero(struct vm_map *new_map, struct vm_map *old_map,
    struct vm_map_entry *old_entry)
{
	struct vm_map_entry *new_entry;

	new_entry = uvm_mapent_clone(new_map, old_entry, 0);

	new_entry->etype |=
	    (UVM_ET_COPYONWRITE|UVM_ET_NEEDSCOPY);

	if (new_entry->aref.ar_amap) {
		uvm_map_unreference_amap(new_entry, 0);
		new_entry->aref.ar_pageoff = 0;
		new_entry->aref.ar_amap = NULL;
	}

	if (UVM_ET_ISOBJ(new_entry)) {
		if (new_entry->object.uvm_obj->pgops->pgo_detach)
			new_entry->object.uvm_obj->pgops->pgo_detach(
			    new_entry->object.uvm_obj);
		new_entry->object.uvm_obj = NULL;
		new_entry->offset = 0;
		new_entry->etype &= ~UVM_ET_OBJ;
	}
}

/*
 *   F O R K   -   m a i n   e n t r y   p o i n t
 */
/*
 * uvmspace_fork: fork a process' main map
 *
 * => create a new vmspace for child process from parent.
 * => parent's map must not be locked.
 */

struct vmspace *
uvmspace_fork(struct vmspace *vm1)
{
	struct vmspace *vm2;
	struct vm_map *old_map = &vm1->vm_map;
	struct vm_map *new_map;
	struct vm_map_entry *old_entry;
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	vm_map_lock(old_map);

	vm2 = uvmspace_alloc(vm_map_min(old_map), vm_map_max(old_map),
	    vm1->vm_map.flags & VM_MAP_TOPDOWN);
	memcpy(&vm2->vm_startcopy, &vm1->vm_startcopy,
	    (char *) (vm1 + 1) - (char *) &vm1->vm_startcopy);
	new_map = &vm2->vm_map;		  /* XXX */

	old_entry = old_map->header.next;
	new_map->size = old_map->size;

	/*
	 * go entry-by-entry
	 */

	while (old_entry != &old_map->header) {

		/*
		 * first, some sanity checks on the old entry
		 */

		KASSERT(!UVM_ET_ISSUBMAP(old_entry));
		KASSERT(UVM_ET_ISCOPYONWRITE(old_entry) ||
			!UVM_ET_ISNEEDSCOPY(old_entry));

		switch (old_entry->inheritance) {
		case MAP_INHERIT_NONE:
			/*
			 * drop the mapping, modify size
			 */
			new_map->size -= old_entry->end - old_entry->start;
			break;

		case MAP_INHERIT_SHARE:
			uvm_mapent_forkshared(new_map, old_map, old_entry);
			break;

		case MAP_INHERIT_COPY:
			uvm_mapent_forkcopy(new_map, old_map, old_entry);
			break;

		case MAP_INHERIT_ZERO:
			uvm_mapent_forkzero(new_map, old_map, old_entry);
			break;
		default:
			KASSERT(0);
			break;
		}
		old_entry = old_entry->next;
	}

	pmap_update(old_map->pmap);
	vm_map_unlock(old_map);

	if (uvm_shmfork && vm1->vm_shm)
		(*uvm_shmfork)(vm1, vm2);

#ifdef PMAP_FORK
	pmap_fork(vm1->vm_map.pmap, vm2->vm_map.pmap);
#endif

	UVMHIST_LOG(maphist,"<- done",0,0,0,0);
	return (vm2);
}


/*
 * uvm_mapent_trymerge: try to merge an entry with its neighbors.
 *
 * => called with map locked.
 * => return non zero if successfully merged.
 */

int
uvm_mapent_trymerge(struct vm_map *map, struct vm_map_entry *entry, int flags)
{
	struct uvm_object *uobj;
	struct vm_map_entry *next;
	struct vm_map_entry *prev;
	vsize_t size;
	int merged = 0;
	bool copying;
	int newetype;

	if (entry->aref.ar_amap != NULL) {
		return 0;
	}
	if ((entry->flags & UVM_MAP_NOMERGE) != 0) {
		return 0;
	}

	uobj = entry->object.uvm_obj;
	size = entry->end - entry->start;
	copying = (flags & UVM_MERGE_COPYING) != 0;
	newetype = copying ? (entry->etype & ~UVM_ET_NEEDSCOPY) : entry->etype;

	next = entry->next;
	if (next != &map->header &&
	    next->start == entry->end &&
	    ((copying && next->aref.ar_amap != NULL &&
	    amap_refs(next->aref.ar_amap) == 1) ||
	    (!copying && next->aref.ar_amap == NULL)) &&
	    UVM_ET_ISCOMPATIBLE(next, newetype,
	    uobj, entry->flags, entry->protection,
	    entry->max_protection, entry->inheritance, entry->advice,
	    entry->wired_count) &&
	    (uobj == NULL || entry->offset + size == next->offset)) {
		int error;

		if (copying) {
			error = amap_extend(next, size,
			    AMAP_EXTEND_NOWAIT|AMAP_EXTEND_BACKWARDS);
		} else {
			error = 0;
		}
		if (error == 0) {
			if (uobj) {
				if (uobj->pgops->pgo_detach) {
					uobj->pgops->pgo_detach(uobj);
				}
			}

			entry->end = next->end;
			clear_hints(map, next);
			uvm_map_entry_unlink(map, next);
			if (copying) {
				entry->aref = next->aref;
				entry->etype &= ~UVM_ET_NEEDSCOPY;
			}
			uvm_map_check(map, "trymerge forwardmerge");
			uvm_mapent_free(next);
			merged++;
		}
	}

	prev = entry->prev;
	if (prev != &map->header &&
	    prev->end == entry->start &&
	    ((copying && !merged && prev->aref.ar_amap != NULL &&
	    amap_refs(prev->aref.ar_amap) == 1) ||
	    (!copying && prev->aref.ar_amap == NULL)) &&
	    UVM_ET_ISCOMPATIBLE(prev, newetype,
	    uobj, entry->flags, entry->protection,
	    entry->max_protection, entry->inheritance, entry->advice,
	    entry->wired_count) &&
	    (uobj == NULL ||
	    prev->offset + prev->end - prev->start == entry->offset)) {
		int error;

		if (copying) {
			error = amap_extend(prev, size,
			    AMAP_EXTEND_NOWAIT|AMAP_EXTEND_FORWARDS);
		} else {
			error = 0;
		}
		if (error == 0) {
			if (uobj) {
				if (uobj->pgops->pgo_detach) {
					uobj->pgops->pgo_detach(uobj);
				}
				entry->offset = prev->offset;
			}

			entry->start = prev->start;
			clear_hints(map, prev);
			uvm_map_entry_unlink(map, prev);
			if (copying) {
				entry->aref = prev->aref;
				entry->etype &= ~UVM_ET_NEEDSCOPY;
			}
			uvm_map_check(map, "trymerge backmerge");
			uvm_mapent_free(prev);
			merged++;
		}
	}

	return merged;
}

/*
 * uvm_map_setup: init map
 *
 * => map must not be in service yet.
 */

void
uvm_map_setup(struct vm_map *map, vaddr_t vmin, vaddr_t vmax, int flags)
{

	rb_tree_init(&map->rb_tree, &uvm_map_tree_ops);
	map->header.next = map->header.prev = &map->header;
	map->nentries = 0;
	map->size = 0;
	map->ref_count = 1;
	vm_map_setmin(map, vmin);
	vm_map_setmax(map, vmax);
	map->flags = flags;
	map->first_free = &map->header;
	map->hint = &map->header;
	map->timestamp = 0;
	map->busy = NULL;

	rw_init(&map->lock);
	cv_init(&map->cv, "vm_map");
	mutex_init(&map->misc_lock, MUTEX_DRIVER, IPL_NONE);
}

/*
 *   U N M A P   -   m a i n   e n t r y   p o i n t
 */

/*
 * uvm_unmap1: remove mappings from a vm_map (from "start" up to "stop")
 *
 * => caller must check alignment and size
 * => map must be unlocked (we will lock it)
 * => flags is UVM_FLAG_QUANTUM or 0.
 */

void
uvm_unmap1(struct vm_map *map, vaddr_t start, vaddr_t end, int flags)
{
	struct vm_map_entry *dead_entries;
	UVMHIST_FUNC(__func__);
	UVMHIST_CALLARGS(maphist, "  (map=%#jx, start=%#jx, end=%#jx)",
	    (uintptr_t)map, start, end, 0);

	KASSERTMSG(start < end,
	    "%s: map %p: start %#jx < end %#jx", __func__, map,
	    (uintmax_t)start, (uintmax_t)end);
	if (map == kernel_map) {
		LOCKDEBUG_MEM_CHECK((void *)start, end - start);
	}

	/*
	 * work now done by helper functions.   wipe the pmap's and then
	 * detach from the dead entries...
	 */
	vm_map_lock(map);
	uvm_unmap_remove(map, start, end, &dead_entries, flags);
	vm_map_unlock(map);

	if (dead_entries != NULL)
		uvm_unmap_detach(dead_entries, 0);

	UVMHIST_LOG(maphist, "<- done", 0,0,0,0);
}


/*
 * uvm_map_reference: add reference to a map
 *
 * => map need not be locked
 */

void
uvm_map_reference(struct vm_map *map)
{

	atomic_inc_uint(&map->ref_count);
}

void
uvm_map_lock_entry(struct vm_map_entry *entry, krw_t op)
{

	if (entry->aref.ar_amap != NULL) {
		amap_lock(entry->aref.ar_amap, op);
	}
	if (UVM_ET_ISOBJ(entry)) {
		rw_enter(entry->object.uvm_obj->vmobjlock, op);
	}
}

void
uvm_map_unlock_entry(struct vm_map_entry *entry)
{

	if (UVM_ET_ISOBJ(entry)) {
		rw_exit(entry->object.uvm_obj->vmobjlock);
	}
	if (entry->aref.ar_amap != NULL) {
		amap_unlock(entry->aref.ar_amap);
	}
}

#define	UVM_VOADDR_TYPE_MASK	0x3UL
#define	UVM_VOADDR_TYPE_UOBJ	0x1UL
#define	UVM_VOADDR_TYPE_ANON	0x2UL
#define	UVM_VOADDR_OBJECT_MASK	~UVM_VOADDR_TYPE_MASK

#define	UVM_VOADDR_GET_TYPE(voa)					\
	((voa)->object & UVM_VOADDR_TYPE_MASK)
#define	UVM_VOADDR_GET_OBJECT(voa)					\
	((voa)->object & UVM_VOADDR_OBJECT_MASK)
#define	UVM_VOADDR_SET_OBJECT(voa, obj, type)				\
do {									\
	KASSERT(((uintptr_t)(obj) & UVM_VOADDR_TYPE_MASK) == 0);	\
	(voa)->object = ((uintptr_t)(obj)) | (type);			\
} while (/*CONSTCOND*/0)

#define	UVM_VOADDR_GET_UOBJ(voa)					\
	((struct uvm_object *)UVM_VOADDR_GET_OBJECT(voa))
#define	UVM_VOADDR_SET_UOBJ(voa, uobj)					\
	UVM_VOADDR_SET_OBJECT(voa, uobj, UVM_VOADDR_TYPE_UOBJ)

#define	UVM_VOADDR_GET_ANON(voa)					\
	((struct vm_anon *)UVM_VOADDR_GET_OBJECT(voa))
#define	UVM_VOADDR_SET_ANON(voa, anon)					\
	UVM_VOADDR_SET_OBJECT(voa, anon, UVM_VOADDR_TYPE_ANON)

/*
 * uvm_voaddr_acquire: returns the virtual object address corresponding
 * to the specified virtual address.
 *
 * => resolves COW so the true page identity is tracked.
 *
 * => acquires a reference on the page's owner (uvm_object or vm_anon)
 */
bool
uvm_voaddr_acquire(struct vm_map * const map, vaddr_t const va,
    struct uvm_voaddr * const voaddr)
{
	struct vm_map_entry *entry;
	struct vm_anon *anon = NULL;
	bool result = false;
	bool exclusive = false;
	void (*unlock_fn)(struct vm_map *);

	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);
	UVMHIST_LOG(maphist,"(map=%#jx,va=%#jx)", (uintptr_t)map, va, 0, 0);

	const vaddr_t start = trunc_page(va);
	const vaddr_t end = round_page(va+1);

 lookup_again:
	if (__predict_false(exclusive)) {
		vm_map_lock(map);
		unlock_fn = vm_map_unlock;
	} else {
		vm_map_lock_read(map);
		unlock_fn = vm_map_unlock_read;
	}

	if (__predict_false(!uvm_map_lookup_entry(map, start, &entry))) {
		unlock_fn(map);
		UVMHIST_LOG(maphist,"<- done (no entry)",0,0,0,0);
		return false;
	}

	if (__predict_false(entry->protection == VM_PROT_NONE)) {
		unlock_fn(map);
		UVMHIST_LOG(maphist,"<- done (PROT_NONE)",0,0,0,0);
		return false;
	}

	/*
	 * We have a fast path for the common case of "no COW resolution
	 * needed" whereby we have taken a read lock on the map and if
	 * we don't encounter any need to create a vm_anon then great!
	 * But if we do, we loop around again, instead taking an exclusive
	 * lock so that we can perform the fault.
	 *
	 * In the event that we have to resolve the fault, we do nearly the
	 * same work as uvm_map_pageable() does:
	 *
	 * 1: holding the write lock, we create any anonymous maps that need
	 *    to be created.  however, we do NOT need to clip the map entries
	 *    in this case.
	 *
	 * 2: we downgrade to a read lock, and call uvm_fault_wire to fault
	 *    in the page (assuming the entry is not already wired).  this
	 *    is done because we need the vm_anon to be present.
	 */
	if (__predict_true(!VM_MAPENT_ISWIRED(entry))) {

		bool need_fault = false;

		/*
		 * perform the action of vm_map_lookup that need the
		 * write lock on the map: create an anonymous map for
		 * a copy-on-write region, or an anonymous map for
		 * a zero-fill region.
		 */
		if (__predict_false(UVM_ET_ISSUBMAP(entry))) {
			unlock_fn(map);
			UVMHIST_LOG(maphist,"<- done (submap)",0,0,0,0);
			return false;
		}
		if (__predict_false(UVM_ET_ISNEEDSCOPY(entry) &&
		    ((entry->max_protection & VM_PROT_WRITE) ||
		     (entry->object.uvm_obj == NULL)))) {
			if (!exclusive) {
				/* need to take the slow path */
				KASSERT(unlock_fn == vm_map_unlock_read);
				vm_map_unlock_read(map);
				exclusive = true;
				goto lookup_again;
			}
			need_fault = true;
			amap_copy(map, entry, 0, start, end);
			/* XXXCDC: wait OK? */
		}

		/*
		 * do a quick check to see if the fault has already
		 * been resolved to the upper layer.
		 */
		if (__predict_true(entry->aref.ar_amap != NULL &&
				   need_fault == false)) {
			amap_lock(entry->aref.ar_amap, RW_WRITER);
			anon = amap_lookup(&entry->aref, start - entry->start);
			if (__predict_true(anon != NULL)) {
				/* amap unlocked below */
				goto found_anon;
			}
			amap_unlock(entry->aref.ar_amap);
			need_fault = true;
		}

		/*
		 * we predict this test as false because if we reach
		 * this point, then we are likely dealing with a
		 * shared memory region backed by a uvm_object, in
		 * which case a fault to create the vm_anon is not
		 * necessary.
		 */
		if (__predict_false(need_fault)) {
			if (exclusive) {
				vm_map_busy(map);
				vm_map_unlock(map);
				unlock_fn = vm_map_unbusy;
			}

			if (uvm_fault_wire(map, start, end,
					   entry->max_protection, 1)) {
				/* wiring failed */
				unlock_fn(map);
				UVMHIST_LOG(maphist,"<- done (wire failed)",
					    0,0,0,0);
				return false;
			}

			/*
			 * now that we have resolved the fault, we can unwire
			 * the page.
			 */
			if (exclusive) {
				vm_map_lock(map);
				vm_map_unbusy(map);
				unlock_fn = vm_map_unlock;
			}

			uvm_fault_unwire_locked(map, start, end);
		}
	}

	/* check the upper layer */
	if (entry->aref.ar_amap) {
		amap_lock(entry->aref.ar_amap, RW_WRITER);
		anon = amap_lookup(&entry->aref, start - entry->start);
		if (anon) {
 found_anon:		KASSERT(anon->an_lock == entry->aref.ar_amap->am_lock);
			anon->an_ref++;
			rw_obj_hold(anon->an_lock);
			KASSERT(anon->an_ref != 0);
			UVM_VOADDR_SET_ANON(voaddr, anon);
			voaddr->offset = va & PAGE_MASK;
			result = true;
		}
		amap_unlock(entry->aref.ar_amap);
	}

	/* check the lower layer */
	if (!result && UVM_ET_ISOBJ(entry)) {
		struct uvm_object *uobj = entry->object.uvm_obj;

		KASSERT(uobj != NULL);
		(*uobj->pgops->pgo_reference)(uobj);
		UVM_VOADDR_SET_UOBJ(voaddr, uobj);
		voaddr->offset = entry->offset + (va - entry->start);
		result = true;
	}

	unlock_fn(map);

	if (result) {
		UVMHIST_LOG(maphist,
		    "<- done OK (type=%jd,owner=%#jx,offset=%#jx)",
		    UVM_VOADDR_GET_TYPE(voaddr),
		    UVM_VOADDR_GET_OBJECT(voaddr),
		    voaddr->offset, 0);
	} else {
		UVMHIST_LOG(maphist,"<- done (failed)",0,0,0,0);
	}

	return result;
}

/*
 * uvm_voaddr_release: release the references held by the
 * vitual object address.
 */
void
uvm_voaddr_release(struct uvm_voaddr * const voaddr)
{

	switch (UVM_VOADDR_GET_TYPE(voaddr)) {
	case UVM_VOADDR_TYPE_UOBJ: {
		struct uvm_object * const uobj = UVM_VOADDR_GET_UOBJ(voaddr);

		KASSERT(uobj != NULL);
		KASSERT(uobj->pgops->pgo_detach != NULL);
		(*uobj->pgops->pgo_detach)(uobj);
		break;
	    }
	case UVM_VOADDR_TYPE_ANON: {
		struct vm_anon * const anon = UVM_VOADDR_GET_ANON(voaddr);
		krwlock_t *lock;

		KASSERT(anon != NULL);
		rw_enter((lock = anon->an_lock), RW_WRITER);
	    	KASSERT(anon->an_ref > 0);
		if (--anon->an_ref == 0) {
			uvm_anfree(anon);
		}
		rw_exit(lock);
		rw_obj_free(lock);
	    	break;
	    }
	default:
		panic("uvm_voaddr_release: bad type");
	}
	memset(voaddr, 0, sizeof(*voaddr));
}

/*
 * uvm_voaddr_compare: compare two uvm_voaddr objects.
 *
 * => memcmp() semantics
 */
int
uvm_voaddr_compare(const struct uvm_voaddr * const voaddr1,
    const struct uvm_voaddr * const voaddr2)
{
	const uintptr_t type1 = UVM_VOADDR_GET_TYPE(voaddr1);
	const uintptr_t type2 = UVM_VOADDR_GET_TYPE(voaddr2);

	KASSERT(type1 == UVM_VOADDR_TYPE_UOBJ ||
		type1 == UVM_VOADDR_TYPE_ANON);

	KASSERT(type2 == UVM_VOADDR_TYPE_UOBJ ||
		type2 == UVM_VOADDR_TYPE_ANON);

	if (type1 < type2)
		return -1;
	if (type1 > type2)
		return 1;

	const uintptr_t addr1 = UVM_VOADDR_GET_OBJECT(voaddr1);
	const uintptr_t addr2 = UVM_VOADDR_GET_OBJECT(voaddr2);

	if (addr1 < addr2)
		return -1;
	if (addr1 > addr2)
		return 1;

	if (voaddr1->offset < voaddr2->offset)
		return -1;
	if (voaddr1->offset > voaddr2->offset)
		return 1;

	return 0;
}

#if defined(DDB) || defined(DEBUGPRINT)

/*
 * uvm_map_printit: actually prints the map
 */

void
uvm_map_printit(struct vm_map *map, bool full,
    void (*pr)(const char *, ...))
{
	struct vm_map_entry *entry;

	(*pr)("MAP %p: [%#lx->%#lx]\n", map, vm_map_min(map),
	    vm_map_max(map));
	(*pr)("\t#ent=%d, sz=%d, ref=%d, version=%d, flags=%#x\n",
	    map->nentries, map->size, map->ref_count, map->timestamp,
	    map->flags);
	(*pr)("\tpmap=%p(resident=%ld, wired=%ld)\n", map->pmap,
	    pmap_resident_count(map->pmap), pmap_wired_count(map->pmap));
	if (!full)
		return;
	for (entry = map->header.next; entry != &map->header;
	    entry = entry->next) {
		(*pr)(" - %p: %#lx->%#lx: obj=%p/%#llx, amap=%p/%d\n",
		    entry, entry->start, entry->end, entry->object.uvm_obj,
		    (long long)entry->offset, entry->aref.ar_amap,
		    entry->aref.ar_pageoff);
		(*pr)(
		    "\tsubmap=%c, cow=%c, nc=%c, prot(max)=%d/%d, inh=%d, "
		    "wc=%d, adv=%d%s\n",
		    (entry->etype & UVM_ET_SUBMAP) ? 'T' : 'F',
		    (entry->etype & UVM_ET_COPYONWRITE) ? 'T' : 'F',
		    (entry->etype & UVM_ET_NEEDSCOPY) ? 'T' : 'F',
		    entry->protection, entry->max_protection,
		    entry->inheritance, entry->wired_count, entry->advice,
		    entry == map->first_free ? " (first_free)" : "");
	}
}

void
uvm_whatis(uintptr_t addr, void (*pr)(const char *, ...))
{
	struct vm_map *map;

	for (map = kernel_map;;) {
		struct vm_map_entry *entry;

		if (!uvm_map_lookup_entry_bytree(map, (vaddr_t)addr, &entry)) {
			break;
		}
		(*pr)("%p is %p+%zu from VMMAP %p\n",
		    (void *)addr, (void *)entry->start,
		    (size_t)(addr - (uintptr_t)entry->start), map);
		if (!UVM_ET_ISSUBMAP(entry)) {
			break;
		}
		map = entry->object.sub_map;
	}
}

#endif /* DDB || DEBUGPRINT */

#ifndef __USER_VA0_IS_SAFE
static int
sysctl_user_va0_disable(SYSCTLFN_ARGS)
{
	struct sysctlnode node;
	int t, error;

	node = *rnode;
	node.sysctl_data = &t;
	t = user_va0_disable;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	if (!t && user_va0_disable &&
	    kauth_authorize_system(l->l_cred, KAUTH_SYSTEM_MAP_VA_ZERO, 0,
	    NULL, NULL, NULL))
		return EPERM;

	user_va0_disable = !!t;
	return 0;
}
#endif

static int
fill_vmentry(struct lwp *l, struct proc *p, struct kinfo_vmentry *kve,
    struct vm_map *m, struct vm_map_entry *e)
{
#ifndef _RUMPKERNEL
	int error;

	memset(kve, 0, sizeof(*kve));
	KASSERT(e != NULL);
	if (UVM_ET_ISOBJ(e)) {
		struct uvm_object *uobj = e->object.uvm_obj;
		KASSERT(uobj != NULL);
		kve->kve_ref_count = uobj->uo_refs;
		kve->kve_count = uobj->uo_npages;
		if (UVM_OBJ_IS_VNODE(uobj)) {
			struct vattr va;
			struct vnode *vp = (struct vnode *)uobj;
			vn_lock(vp, LK_SHARED | LK_RETRY);
			error = VOP_GETATTR(vp, &va, l->l_cred);
			VOP_UNLOCK(vp);
			kve->kve_type = KVME_TYPE_VNODE;
			if (error == 0) {
				kve->kve_vn_size = vp->v_size;
				kve->kve_vn_type = (int)vp->v_type;
				kve->kve_vn_mode = va.va_mode;
				kve->kve_vn_rdev = va.va_rdev;
				kve->kve_vn_fileid = va.va_fileid;
				kve->kve_vn_fsid = va.va_fsid;
				error = vnode_to_path(kve->kve_path,
				    sizeof(kve->kve_path) / 2, vp, l, p);
			}
		} else if (UVM_OBJ_IS_KERN_OBJECT(uobj)) {
			kve->kve_type = KVME_TYPE_KERN;
		} else if (UVM_OBJ_IS_DEVICE(uobj)) {
			kve->kve_type = KVME_TYPE_DEVICE;
		} else if (UVM_OBJ_IS_AOBJ(uobj)) {
			kve->kve_type = KVME_TYPE_ANON;
		} else {
			kve->kve_type = KVME_TYPE_OBJECT;
		}
	} else if (UVM_ET_ISSUBMAP(e)) {
		struct vm_map *map = e->object.sub_map;
		KASSERT(map != NULL);
		kve->kve_ref_count = map->ref_count;
		kve->kve_count = map->nentries;
		kve->kve_type = KVME_TYPE_SUBMAP;
	} else
		kve->kve_type = KVME_TYPE_UNKNOWN;

	kve->kve_start = e->start;
	kve->kve_end = e->end;
	kve->kve_offset = e->offset;
	kve->kve_wired_count = e->wired_count;
	kve->kve_inheritance = e->inheritance;
	kve->kve_attributes = 0; /* unused */
	kve->kve_advice = e->advice;
#define PROT(p) (((p) & VM_PROT_READ) ? KVME_PROT_READ : 0) | \
	(((p) & VM_PROT_WRITE) ? KVME_PROT_WRITE : 0) | \
	(((p) & VM_PROT_EXECUTE) ? KVME_PROT_EXEC : 0)
	kve->kve_protection = PROT(e->protection);
	kve->kve_max_protection = PROT(e->max_protection);
	kve->kve_flags |= (e->etype & UVM_ET_COPYONWRITE)
	    ? KVME_FLAG_COW : 0;
	kve->kve_flags |= (e->etype & UVM_ET_NEEDSCOPY)
	    ? KVME_FLAG_NEEDS_COPY : 0;
	kve->kve_flags |= (m->flags & VM_MAP_TOPDOWN)
	    ? KVME_FLAG_GROWS_DOWN : KVME_FLAG_GROWS_UP;
	kve->kve_flags |= (m->flags & VM_MAP_PAGEABLE)
	    ? KVME_FLAG_PAGEABLE : 0;
#endif
	return 0;
}

static int
fill_vmentries(struct lwp *l, pid_t pid, u_int elem_size, void *oldp,
    size_t *oldlenp)
{
	int error;
	struct proc *p;
	struct kinfo_vmentry *vme;
	struct vmspace *vm;
	struct vm_map *map;
	struct vm_map_entry *entry;
	char *dp;
	size_t count, vmesize;

	if (elem_size == 0 || elem_size > 2 * sizeof(*vme))
		return EINVAL;

	if (oldp) {
		if (*oldlenp > 10UL * 1024UL * 1024UL)
			return E2BIG;
		count = *oldlenp / elem_size;
		if (count == 0)
			return ENOMEM;
		vmesize = count * sizeof(*vme);
	} else
		vmesize = 0;

	if ((error = proc_find_locked(l, &p, pid)) != 0)
		return error;

	vme = NULL;
	count = 0;

	if ((error = proc_vmspace_getref(p, &vm)) != 0)
		goto out;

	map = &vm->vm_map;
	vm_map_lock_read(map);

	dp = oldp;
	if (oldp)
		vme = kmem_alloc(vmesize, KM_SLEEP);
	for (entry = map->header.next; entry != &map->header;
	    entry = entry->next) {
		if (oldp && (dp - (char *)oldp) < vmesize) {
			error = fill_vmentry(l, p, &vme[count], map, entry);
			if (error)
				goto out;
			dp += elem_size;
		}
		count++;
	}
	vm_map_unlock_read(map);
	uvmspace_free(vm);

out:
	if (pid != -1)
		mutex_exit(p->p_lock);
	if (error == 0) {
		const u_int esize = uimin(sizeof(*vme), elem_size);
		dp = oldp;
		for (size_t i = 0; i < count; i++) {
			if (oldp && (dp - (char *)oldp) < vmesize) {
				error = sysctl_copyout(l, &vme[i], dp, esize);
				if (error)
					break;
				dp += elem_size;
			} else
				break;
		}
		count *= elem_size;
		if (oldp != NULL && *oldlenp < count)
			error = ENOSPC;
		*oldlenp = count;
	}
	if (vme)
		kmem_free(vme, vmesize);
	return error;
}

static int
sysctl_vmproc(SYSCTLFN_ARGS)
{
	int error;

	if (namelen == 1 && name[0] == CTL_QUERY)
		return (sysctl_query(SYSCTLFN_CALL(rnode)));

	if (namelen == 0)
		return EINVAL;

	switch (name[0]) {
	case VM_PROC_MAP:
		if (namelen != 3)
			return EINVAL;
		sysctl_unlock();
		error = fill_vmentries(l, name[1], name[2], oldp, oldlenp);
		sysctl_relock();
		return error;
	default:
		return EINVAL;
	}
}

SYSCTL_SETUP(sysctl_uvmmap_setup, "sysctl uvmmap setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "proc",
		       SYSCTL_DESCR("Process vm information"),
		       sysctl_vmproc, 0, NULL, 0,
		       CTL_VM, VM_PROC, CTL_EOL);
#ifndef __USER_VA0_IS_SAFE
        sysctl_createv(clog, 0, NULL, NULL,
                       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
                       CTLTYPE_INT, "user_va0_disable",
                       SYSCTL_DESCR("Disable VA 0"),
                       sysctl_user_va0_disable, 0, &user_va0_disable, 0,
                       CTL_VM, CTL_CREATE, CTL_EOL);
#endif
}
