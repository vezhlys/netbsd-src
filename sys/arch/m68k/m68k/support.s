/*	$NetBSD: support.s,v 1.10 2024/01/16 15:38:59 thorpej Exp $	*/

/*
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1980, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 * from: Utah $Hdr: locore.s 1.66 92/12/22$
 *
 *	@(#)locore.s	8.6 (Berkeley) 5/27/94
 */

/*
 * Miscellaneous support routines common to all m68k ports.
 */

#include <machine/asm.h>

#include "assym.h"

	.file	"support.s"
	.text

/*
 * non-local gotos
 */
ENTRY(setjmp)
	movl	4(%sp),%a0	| savearea pointer
	moveml	#0xFCFC,(%a0)	| save d2-d7/a2-a7
	movl	(%sp),48(%a0)	| and return address
	moveq	#0,%d0		| return 0
	rts

ENTRY(longjmp)
	movl	4(%sp),%a0
	moveml	(%a0)+,#0xFCFC
	movl	(%a0),(%sp)
	moveq	#1,%d0
	rts
