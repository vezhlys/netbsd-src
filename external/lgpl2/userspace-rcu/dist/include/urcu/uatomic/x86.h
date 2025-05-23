// SPDX-FileCopyrightText: 1991-1994 by Xerox Corporation.  All rights reserved.
// SPDX-FileCopyrightText: 1996-1999 by Silicon Graphics.  All rights reserved.
// SPDX-FileCopyrightText: 1999-2004 Hewlett-Packard Development Company, L.P.
// SPDX-FileCopyrightText: 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: LicenseRef-Boehm-GC

#ifndef _URCU_ARCH_UATOMIC_X86_H
#define _URCU_ARCH_UATOMIC_X86_H

#include <stdlib.h>		/* For abort(3). */

/*
 * Code inspired from libuatomic_ops-1.2, inherited in part from the
 * Boehm-Demers-Weiser conservative garbage collector.
 */

#include <urcu/arch.h>
#include <urcu/config.h>
#include <urcu/compiler.h>
#include <urcu/system.h>

#define UATOMIC_HAS_ATOMIC_BYTE
#define UATOMIC_HAS_ATOMIC_SHORT

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Derived from AO_compare_and_swap() and AO_test_and_set_full().
 */

/*
 * The __hp() macro casts the void pointer @x to a pointer to a structure
 * containing an array of char of the specified size. This allows passing the
 * @addr arguments of the following inline functions as "m" and "+m" operands
 * to the assembly. The @size parameter should be a constant to support
 * compilers such as clang which do not support VLA. Create typedefs because
 * C++ does not allow types be defined in casts.
 */

typedef struct { char v[1]; } __hp_1;
typedef struct { char v[2]; } __hp_2;
typedef struct { char v[4]; } __hp_4;
typedef struct { char v[8]; } __hp_8;

#define __hp(size, x)	((__hp_##size *)(x))

/* cmpxchg */

static inline __attribute__((always_inline))
unsigned long __uatomic_cmpxchg(void *addr, unsigned long old,
			      unsigned long _new, int len)
{
	switch (len) {
	case 1:
	{
		unsigned char result = old;

		__asm__ __volatile__(
		"lock; cmpxchgb %2, %1"
			: "+a"(result), "+m"(*__hp(1, addr))
			: "q"((unsigned char)_new)
			: "memory");
		return result;
	}
	case 2:
	{
		unsigned short result = old;

		__asm__ __volatile__(
		"lock; cmpxchgw %2, %1"
			: "+a"(result), "+m"(*__hp(2, addr))
			: "r"((unsigned short)_new)
			: "memory");
		return result;
	}
	case 4:
	{
		unsigned int result = old;

		__asm__ __volatile__(
		"lock; cmpxchgl %2, %1"
			: "+a"(result), "+m"(*__hp(4, addr))
			: "r"((unsigned int)_new)
			: "memory");
		return result;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		unsigned long result = old;

		__asm__ __volatile__(
		"lock; cmpxchgq %2, %1"
			: "+a"(result), "+m"(*__hp(8, addr))
			: "r"((unsigned long)_new)
			: "memory");
		return result;
	}
#endif
	}
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__("ud2");
	return 0;
}

#define _uatomic_cmpxchg(addr, old, _new)				      \
	((__typeof__(*(addr))) __uatomic_cmpxchg((addr),		      \
						caa_cast_long_keep_sign(old), \
						caa_cast_long_keep_sign(_new),\
						sizeof(*(addr))))

/* xchg */

static inline __attribute__((always_inline))
unsigned long __uatomic_exchange(void *addr, unsigned long val, int len)
{
	/* Note: the "xchg" instruction does not need a "lock" prefix. */
	switch (len) {
	case 1:
	{
		unsigned char result;
		__asm__ __volatile__(
		"xchgb %0, %1"
			: "=q"(result), "+m"(*__hp(1, addr))
			: "0" ((unsigned char)val)
			: "memory");
		return result;
	}
	case 2:
	{
		unsigned short result;
		__asm__ __volatile__(
		"xchgw %0, %1"
			: "=r"(result), "+m"(*__hp(2, addr))
			: "0" ((unsigned short)val)
			: "memory");
		return result;
	}
	case 4:
	{
		unsigned int result;
		__asm__ __volatile__(
		"xchgl %0, %1"
			: "=r"(result), "+m"(*__hp(4, addr))
			: "0" ((unsigned int)val)
			: "memory");
		return result;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		unsigned long result;
		__asm__ __volatile__(
		"xchgq %0, %1"
			: "=r"(result), "+m"(*__hp(8, addr))
			: "0" ((unsigned long)val)
			: "memory");
		return result;
	}
#endif
	}
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__("ud2");
	return 0;
}

#define _uatomic_xchg(addr, v)						      \
	((__typeof__(*(addr))) __uatomic_exchange((addr),		      \
						caa_cast_long_keep_sign(v),   \
						sizeof(*(addr))))

/* uatomic_add_return */

static inline __attribute__((always_inline))
unsigned long __uatomic_add_return(void *addr, unsigned long val,
				 int len)
{
	switch (len) {
	case 1:
	{
		unsigned char result = val;

		__asm__ __volatile__(
		"lock; xaddb %1, %0"
			: "+m"(*__hp(1, addr)), "+q" (result)
			:
			: "memory");
		return result + (unsigned char)val;
	}
	case 2:
	{
		unsigned short result = val;

		__asm__ __volatile__(
		"lock; xaddw %1, %0"
			: "+m"(*__hp(2, addr)), "+r" (result)
			:
			: "memory");
		return result + (unsigned short)val;
	}
	case 4:
	{
		unsigned int result = val;

		__asm__ __volatile__(
		"lock; xaddl %1, %0"
			: "+m"(*__hp(4, addr)), "+r" (result)
			:
			: "memory");
		return result + (unsigned int)val;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		unsigned long result = val;

		__asm__ __volatile__(
		"lock; xaddq %1, %0"
			: "+m"(*__hp(8, addr)), "+r" (result)
			:
			: "memory");
		return result + (unsigned long)val;
	}
#endif
	}
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__("ud2");
	return 0;
}

#define _uatomic_add_return(addr, v)					    \
	((__typeof__(*(addr))) __uatomic_add_return((addr),		    \
						caa_cast_long_keep_sign(v), \
						sizeof(*(addr))))

/* uatomic_and */

static inline __attribute__((always_inline))
void __uatomic_and(void *addr, unsigned long val, int len)
{
	switch (len) {
	case 1:
	{
		__asm__ __volatile__(
		"lock; andb %1, %0"
			: "=m"(*__hp(1, addr))
			: "iq" ((unsigned char)val)
			: "memory");
		return;
	}
	case 2:
	{
		__asm__ __volatile__(
		"lock; andw %1, %0"
			: "=m"(*__hp(2, addr))
			: "ir" ((unsigned short)val)
			: "memory");
		return;
	}
	case 4:
	{
		__asm__ __volatile__(
		"lock; andl %1, %0"
			: "=m"(*__hp(4, addr))
			: "ir" ((unsigned int)val)
			: "memory");
		return;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		__asm__ __volatile__(
		"lock; andq %1, %0"
			: "=m"(*__hp(8, addr))
			: "er" ((unsigned long)val)
			: "memory");
		return;
	}
#endif
	}
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__("ud2");
	return;
}

#define _uatomic_and(addr, v)						   \
	(__uatomic_and((addr), caa_cast_long_keep_sign(v), sizeof(*(addr))))

/* uatomic_or */

static inline __attribute__((always_inline))
void __uatomic_or(void *addr, unsigned long val, int len)
{
	switch (len) {
	case 1:
	{
		__asm__ __volatile__(
		"lock; orb %1, %0"
			: "=m"(*__hp(1, addr))
			: "iq" ((unsigned char)val)
			: "memory");
		return;
	}
	case 2:
	{
		__asm__ __volatile__(
		"lock; orw %1, %0"
			: "=m"(*__hp(2, addr))
			: "ir" ((unsigned short)val)
			: "memory");
		return;
	}
	case 4:
	{
		__asm__ __volatile__(
		"lock; orl %1, %0"
			: "=m"(*__hp(4, addr))
			: "ir" ((unsigned int)val)
			: "memory");
		return;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		__asm__ __volatile__(
		"lock; orq %1, %0"
			: "=m"(*__hp(8, addr))
			: "er" ((unsigned long)val)
			: "memory");
		return;
	}
#endif
	}
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__("ud2");
	return;
}

#define _uatomic_or(addr, v)						   \
	(__uatomic_or((addr), caa_cast_long_keep_sign(v), sizeof(*(addr))))

/* uatomic_add */

static inline __attribute__((always_inline))
void __uatomic_add(void *addr, unsigned long val, int len)
{
	switch (len) {
	case 1:
	{
		__asm__ __volatile__(
		"lock; addb %1, %0"
			: "=m"(*__hp(1, addr))
			: "iq" ((unsigned char)val)
			: "memory");
		return;
	}
	case 2:
	{
		__asm__ __volatile__(
		"lock; addw %1, %0"
			: "=m"(*__hp(2, addr))
			: "ir" ((unsigned short)val)
			: "memory");
		return;
	}
	case 4:
	{
		__asm__ __volatile__(
		"lock; addl %1, %0"
			: "=m"(*__hp(4, addr))
			: "ir" ((unsigned int)val)
			: "memory");
		return;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		__asm__ __volatile__(
		"lock; addq %1, %0"
			: "=m"(*__hp(8, addr))
			: "er" ((unsigned long)val)
			: "memory");
		return;
	}
#endif
	}
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__("ud2");
	return;
}

#define _uatomic_add(addr, v)						   \
	(__uatomic_add((addr), caa_cast_long_keep_sign(v), sizeof(*(addr))))


/* uatomic_inc */

static inline __attribute__((always_inline))
void __uatomic_inc(void *addr, int len)
{
	switch (len) {
	case 1:
	{
		__asm__ __volatile__(
		"lock; incb %0"
			: "=m"(*__hp(1, addr))
			:
			: "memory");
		return;
	}
	case 2:
	{
		__asm__ __volatile__(
		"lock; incw %0"
			: "=m"(*__hp(2, addr))
			:
			: "memory");
		return;
	}
	case 4:
	{
		__asm__ __volatile__(
		"lock; incl %0"
			: "=m"(*__hp(4, addr))
			:
			: "memory");
		return;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		__asm__ __volatile__(
		"lock; incq %0"
			: "=m"(*__hp(8, addr))
			:
			: "memory");
		return;
	}
#endif
	}
	/* generate an illegal instruction. Cannot catch this with linker tricks
	 * when optimizations are disabled. */
	__asm__ __volatile__("ud2");
	return;
}

#define _uatomic_inc(addr)	(__uatomic_inc((addr), sizeof(*(addr))))

/* uatomic_dec */

static inline __attribute__((always_inline))
void __uatomic_dec(void *addr, int len)
{
	switch (len) {
	case 1:
	{
		__asm__ __volatile__(
		"lock; decb %0"
			: "=m"(*__hp(1, addr))
			:
			: "memory");
		return;
	}
	case 2:
	{
		__asm__ __volatile__(
		"lock; decw %0"
			: "=m"(*__hp(2, addr))
			:
			: "memory");
		return;
	}
	case 4:
	{
		__asm__ __volatile__(
		"lock; decl %0"
			: "=m"(*__hp(4, addr))
			:
			: "memory");
		return;
	}
#if (CAA_BITS_PER_LONG == 64)
	case 8:
	{
		__asm__ __volatile__(
		"lock; decq %0"
			: "=m"(*__hp(8, addr))
			:
			: "memory");
		return;
	}
#endif
	}
	/*
	 * generate an illegal instruction. Cannot catch this with
	 * linker tricks when optimizations are disabled.
	 */
	__asm__ __volatile__("ud2");
	return;
}

#define _uatomic_dec(addr)	(__uatomic_dec((addr), sizeof(*(addr))))

#ifdef URCU_ARCH_X86_NO_CAS

/* For backwards compat */
#define CONFIG_RCU_COMPAT_ARCH 1

extern int __rcu_cas_avail;
extern int __rcu_cas_init(void);

#define UATOMIC_COMPAT(insn)							\
	((caa_likely(__rcu_cas_avail > 0))						\
	? (_uatomic_##insn)							\
		: ((caa_unlikely(__rcu_cas_avail < 0)				\
			? ((__rcu_cas_init() > 0)				\
				? (_uatomic_##insn)				\
				: (compat_uatomic_##insn))			\
			: (compat_uatomic_##insn))))

/*
 * We leave the return value so we don't break the ABI, but remove the
 * return value from the API.
 */
extern unsigned long _compat_uatomic_set(void *addr,
					 unsigned long _new, int len);
#define compat_uatomic_set(addr, _new)				     	       \
	((void) _compat_uatomic_set((addr),				       \
				caa_cast_long_keep_sign(_new),		       \
				sizeof(*(addr))))


extern unsigned long _compat_uatomic_xchg(void *addr,
					  unsigned long _new, int len);
#define compat_uatomic_xchg(addr, _new)					       \
	((__typeof__(*(addr))) _compat_uatomic_xchg((addr),		       \
						caa_cast_long_keep_sign(_new), \
						sizeof(*(addr))))

extern unsigned long _compat_uatomic_cmpxchg(void *addr, unsigned long old,
					     unsigned long _new, int len);
#define compat_uatomic_cmpxchg(addr, old, _new)				       \
	((__typeof__(*(addr))) _compat_uatomic_cmpxchg((addr),		       \
						caa_cast_long_keep_sign(old),  \
						caa_cast_long_keep_sign(_new), \
						sizeof(*(addr))))

extern void _compat_uatomic_and(void *addr, unsigned long _new, int len);
#define compat_uatomic_and(addr, v)				       \
	(_compat_uatomic_and((addr),				       \
			caa_cast_long_keep_sign(v),		       \
			sizeof(*(addr))))

extern void _compat_uatomic_or(void *addr, unsigned long _new, int len);
#define compat_uatomic_or(addr, v)				       \
	(_compat_uatomic_or((addr),				       \
			  caa_cast_long_keep_sign(v),		       \
			  sizeof(*(addr))))

extern unsigned long _compat_uatomic_add_return(void *addr,
						unsigned long _new, int len);
#define compat_uatomic_add_return(addr, v)			            \
	((__typeof__(*(addr))) _compat_uatomic_add_return((addr),     	    \
						caa_cast_long_keep_sign(v), \
						sizeof(*(addr))))

#define compat_uatomic_add(addr, v)					       \
		((void)compat_uatomic_add_return((addr), (v)))
#define compat_uatomic_inc(addr)					       \
		(compat_uatomic_add((addr), 1))
#define compat_uatomic_dec(addr)					       \
		(compat_uatomic_add((addr), -1))

#else
#define UATOMIC_COMPAT(insn)	(_uatomic_##insn)
#endif

/*
 * All RMW operations have an implicit lock prefix.  Thus, ignoring memory
 * ordering for these operations, since they can all be respected by not
 * emitting any memory barrier.
 */

#define uatomic_cmpxchg_mo(addr, old, _new, mos, mof)		\
		UATOMIC_COMPAT(cmpxchg(addr, old, _new))

#define uatomic_xchg_mo(addr, v, mo)		\
		UATOMIC_COMPAT(xchg(addr, v))

#define uatomic_and_mo(addr, v, mo)		\
		UATOMIC_COMPAT(and(addr, v))
#define cmm_smp_mb__before_uatomic_and()	cmm_barrier()
#define cmm_smp_mb__after_uatomic_and()		cmm_barrier()

#define uatomic_or_mo(addr, v, mo)		\
		UATOMIC_COMPAT(or(addr, v))
#define cmm_smp_mb__before_uatomic_or()		cmm_barrier()
#define cmm_smp_mb__after_uatomic_or()		cmm_barrier()

#define uatomic_add_return_mo(addr, v, mo)		\
		UATOMIC_COMPAT(add_return(addr, v))

#define uatomic_add_mo(addr, v, mo)	UATOMIC_COMPAT(add(addr, v))
#define cmm_smp_mb__before_uatomic_add()	cmm_barrier()
#define cmm_smp_mb__after_uatomic_add()		cmm_barrier()

#define uatomic_inc_mo(addr, mo)	UATOMIC_COMPAT(inc(addr))
#define cmm_smp_mb__before_uatomic_inc()	cmm_barrier()
#define cmm_smp_mb__after_uatomic_inc()		cmm_barrier()

#define uatomic_dec_mo(addr, mo)	UATOMIC_COMPAT(dec(addr))
#define cmm_smp_mb__before_uatomic_dec()	cmm_barrier()
#define cmm_smp_mb__after_uatomic_dec()		cmm_barrier()


static inline void _cmm_compat_c11_smp_mb__before_uatomic_load_mo(enum cmm_memorder mo)
{
	/*
	 * A SMP barrier is not necessary for CMM_SEQ_CST because, only a
	 * previous store can be reordered with the load.  However, emitting the
	 * memory barrier after the store is sufficient to prevent reordering
	 * between the two.  This follows toolchains decision of emitting the
	 * memory fence on the stores instead of the loads.
	 *
	 * A compiler barrier is necessary because the underlying operation does
	 * not clobber the registers.
	 */
	switch (mo) {
	case CMM_RELAXED:	/* Fall-through */
	case CMM_ACQUIRE:	/* Fall-through */
	case CMM_CONSUME:	/* Fall-through */
	case CMM_SEQ_CST:	/* Fall-through */
	case CMM_SEQ_CST_FENCE:
		cmm_barrier();
		break;
	case CMM_ACQ_REL:	/* Fall-through */
	case CMM_RELEASE:	/* Fall-through */
	default:
		abort();
		break;
	}
}

static inline void _cmm_compat_c11_smp_mb__after_uatomic_load_mo(enum cmm_memorder mo)
{
	/*
	 * A SMP barrier is not necessary for CMM_SEQ_CST because following
	 * loads and stores cannot be reordered with the load.
	 *
	 * A SMP barrier is however necessary for CMM_SEQ_CST_FENCE to respect
	 * the memory model, since the underlying operation does not have a lock
	 * prefix.
	 *
	 * A compiler barrier is necessary because the underlying operation does
	 * not clobber the registers.
	 */
	switch (mo) {
	case CMM_SEQ_CST_FENCE:
		cmm_smp_mb();
		break;
	case CMM_RELAXED:	/* Fall-through */
	case CMM_ACQUIRE:	/* Fall-through */
	case CMM_CONSUME:	/* Fall-through */
	case CMM_SEQ_CST:
		cmm_barrier();
		break;
	case CMM_ACQ_REL:	/* Fall-through */
	case CMM_RELEASE:	/* Fall-through */
	default:
		abort();
		break;
	}
}

static inline void _cmm_compat_c11_smp_mb__before_uatomic_store_mo(enum cmm_memorder mo)
{
	/*
	 * A SMP barrier is not necessary for CMM_SEQ_CST because the store can
	 * only be reodered with later loads
	 *
	 * A compiler barrier is necessary because the underlying operation does
	 * not clobber the registers.
	 */
	switch (mo) {
	case CMM_RELAXED:	/* Fall-through */
	case CMM_RELEASE:	/* Fall-through */
	case CMM_SEQ_CST:	/* Fall-through */
	case CMM_SEQ_CST_FENCE:
		cmm_barrier();
		break;
	case CMM_ACQ_REL:	/* Fall-through */
	case CMM_ACQUIRE:	/* Fall-through */
	case CMM_CONSUME:	/* Fall-through */
	default:
		abort();
		break;
	}
}

static inline void _cmm_compat_c11_smp_mb__after_uatomic_store_mo(enum cmm_memorder mo)
{
	/*
	 * A SMP barrier is necessary for CMM_SEQ_CST because the store can be
	 * reorded with later loads.  Since no memory barrier is being emitted
	 * before loads, one has to be emitted after the store.  This follows
	 * toolchains decision of emitting the memory fence on the stores instead
	 * of the loads.
	 *
	 * A SMP barrier is necessary for CMM_SEQ_CST_FENCE to respect the
	 * memory model, since the underlying store does not have a lock prefix.
	 *
	 * A compiler barrier is necessary because the underlying operation does
	 * not clobber the registers.
	 */
	switch (mo) {
	case CMM_SEQ_CST:	/* Fall-through */
	case CMM_SEQ_CST_FENCE:
		cmm_smp_mb();
		break;
	case CMM_RELAXED:	/* Fall-through */
	case CMM_RELEASE:
		cmm_barrier();
		break;
	case CMM_ACQ_REL:	/* Fall-through */
	case CMM_ACQUIRE:	/* Fall-through */
	case CMM_CONSUME:	/* Fall-through */
	default:
		abort();
		break;
	}
}

#define _cmm_compat_c11_smp_mb__before_mo(operation, mo)		\
	do {								\
		_cmm_compat_c11_smp_mb__before_ ## operation ## _mo (mo); \
	} while (0)

#define _cmm_compat_c11_smp_mb__after_mo(operation, mo)			\
	do {								\
		_cmm_compat_c11_smp_mb__after_ ## operation ## _mo (mo); \
	} while (0)


#ifdef __cplusplus
}
#endif

#include <urcu/uatomic/generic.h>

#endif /* _URCU_ARCH_UATOMIC_X86_H */
