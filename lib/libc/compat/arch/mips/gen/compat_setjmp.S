/*	$NetBSD: compat_setjmp.S,v 1.7 2025/04/24 01:43:20 riastradh Exp $	*/

/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
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
 */

#include <sys/syscall.h>
#include <mips/asm.h>

#include "assym.h"

#if defined(LIBC_SCCS) && !defined(lint)
#if 0
	RCSID("from: @(#)setjmp.s	8.1 (Berkeley) 6/4/93")
#else
	RCSID("$NetBSD: compat_setjmp.S,v 1.7 2025/04/24 01:43:20 riastradh Exp $")
#endif
#endif /* LIBC_SCCS and not lint */

/*
 * C library -- setjmp, longjmp
 *
 *	longjmp(a,v)
 * will generate a "return(v)" from
 * the last call to
 *	setjmp(a)
 * by restoring registers from the stack,
 * and a struct sigcontext, see <signal.h>
 */

#define SETJMP_FRAME_SIZE	(CALLFRAME_SIZ + STACK_T_SIZE)

NON_LEAF(setjmp, SETJMP_FRAME_SIZE, ra)
	.mask	0x80010000, (CALLFRAME_RA - CALLFRAME_SIZ)
	SETUP_GP
	PTR_SUBU	sp, sp, SETJMP_FRAME_SIZE	# allocate stack frame
	SAVE_GP(CALLFRAME_GP)
	SETUP_GP64(CALLFRAME_GP, setjmp)

	REG_S		ra, CALLFRAME_RA(sp)		# save RA
	REG_S		s0, CALLFRAME_S0(sp)		# save S0
	move		s0, a0				# save sigcontext

	/* Get the signal mask. */
	move		a0, zero			# get current sigmask
	jal		_C_LABEL(sigblock)
	nop
	INT_S		v0, _SC_MASK13(s0)		# save sc_mask13

	/* Get the signal stack. */
	move		a0, zero
	PTR_ADDU	a1, sp, CALLFRAME_SIZ		# pointer to stack_t
	jal		_C_LABEL(__sigaltstack14)

	move		a0, s0				# restore jmpbuf
	INT_L		v1, CALLFRAME_SIZ+_STACK_T_FLAGS(sp)
							# get old ss_onstack
	and		v1, v1, SS_ONSTACK		# extract onstack flag
	INT_S		v1, _SC_ONSTACK(a0)		# save it in sc_onstack

	REG_L		s0, CALLFRAME_S0(sp)		# restore S0
	REG_L		ra, CALLFRAME_RA(sp)		# restore RA
	blt		v0, zero, botch			# check for sigaltstack() error
	nop
	/*
	 * We know we won't need this routine's GP anymore.
	 */
	RESTORE_GP64
	PTR_ADDU	sp, sp, SETJMP_FRAME_SIZE	# pop stack frame

	REG_PROLOGUE
	REG_S	ra, _SC_PC(a0)				# sc_pc = return address
	REG_LI	v0, 0xACEDBADE				# sigcontext magic number
	REG_S	v0, _SC_REGS(a0)			#   saved in sc_regs[0]
	REG_S	s0, _SC_REGS_S0(a0)
	REG_S	s1, _SC_REGS_S1(a0)
	REG_S	s2, _SC_REGS_S2(a0)
	REG_S	s3, _SC_REGS_S3(a0)
	REG_S	s4, _SC_REGS_S4(a0)
	REG_S	s5, _SC_REGS_S5(a0)
	REG_S	s6, _SC_REGS_S6(a0)
	REG_S	s7, _SC_REGS_S7(a0)
	REG_S	gp, _SC_REGS_GP(a0)
	REG_S	sp, _SC_REGS_SP(a0)
	REG_S	s8, _SC_REGS_S8(a0)
#ifdef SOFTFLOAT_FOR_GCC
	INT_S	zero, _SC_FPUSED(a0)			# sc_fpused = 0
#else
	li	v0, 1					# be nice if we could tell
	INT_S	v0, _SC_FPUSED(a0)			# sc_fpused = 1
	cfc1	v0, $31
	INT_S	v0, _SC_FPREGS_FCSR(a0)
#if defined(__mips_o32) || defined(__mips_o64) || defined(__mips_n32)
	FP_S	$f20, _SC_FPREGS_F20(a0)
	FP_S	$f22, _SC_FPREGS_F22(a0)
#endif
#if defined(__mips_o32) || defined(__mips_o64)
	FP_S	$f21, _SC_FPREGS_F21(a0)
	FP_S	$f23, _SC_FPREGS_F23(a0)
#endif
#if defined(__mips_n32) || defined(__mips_n64)
	FP_S	$f24, _SC_FPREGS_F24(a0)
	FP_S	$f26, _SC_FPREGS_F26(a0)
	FP_S	$f28, _SC_FPREGS_F28(a0)
	FP_S	$f30, _SC_FPREGS_F30(a0)
#endif
#if defined(__mips_n64)
	FP_S	$f25, _SC_FPREGS_F25(a0)
	FP_S	$f27, _SC_FPREGS_F27(a0)
	FP_S	$f29, _SC_FPREGS_F29(a0)
	FP_S	$f31, _SC_FPREGS_F31(a0)
#endif
#endif	/* SOFTFLOAT_FOR_GCC */
	REG_EPILOGUE
	move	v0, zero
	j	ra

botch:
	jal	_C_LABEL(abort)
END(setjmp)

LEAF(longjmp)
	SETUP_GP
	PTR_SUBU	sp, sp, CALLFRAME_SIZ
	SAVE_GP(CALLFRAME_S0)
	SETUP_GP64(s0, longjmp)

	beqz		a1, 2f		/* map val 0 -> 1 */
1:
	REG_PROLOGUE
	/* save return value in sc_regs[_R_V0] */
	REG_S		a1, _SC_REGS_V0(a0)
	REG_EPILOGUE

	li		v0, SYS_compat_13_sigreturn13
	syscall

	jal		_C_LABEL(longjmperror)
	jal		_C_LABEL(abort)

2:	li		a1, 1
	b		1b
END(longjmp)
