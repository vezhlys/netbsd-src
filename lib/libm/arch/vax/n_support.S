/*	$NetBSD: n_support.S,v 1.13 2024/07/17 12:00:48 riastradh Exp $	*/
/*
 * Copyright (c) 1985, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)support.s	8.1 (Berkeley) 6/4/93
 */
#include <machine/asm.h>

WEAK_ALIAS(logbl,logb)
WEAK_ALIAS(copysignl, _copysignl)
WEAK_ALIAS(_copysignl, copysign)

	.text
_sccsid:
	.asciz "@(#)support.s\t1.3 (Berkeley) 8/21/85; 8.1 (ucb.elefunt) 6/4/93"

/*
 * copysign(x,y),
 * logb(x),
 * scalb(x,N),
 * finite(x),
 * drem(x,y),
 * Coded in vax assembly language by K.C. Ng,  3/14/85.
 * Revised by K.C. Ng on 4/9/85.
 */

/*
 * double copysign(double x,double y)
 */

ENTRY(copysign, 0)
	movq	4(%ap),%r0		# load x into %r0
	bicw3	$0x807f,%r0,%r2		# mask off the exponent of x
	beql	Lz			# if zero or reserved op then return x
	bicw3	$0x7fff,12(%ap),%r2	# copy the sign bit of y into %r2
	bicw2	$0x8000,%r0		# replace x by |x|
	bisw2	%r2,%r0			# copy the sign bit of y to x
Lz:	ret
END(copysign)

ENTRY(copysignf, 0)
	movl	4(%ap),%r0		# load x into %r0
	bicw3	$0x807f,%r0,%r2		# mask off the exponent of x
	beql	1f			# if zero or reserved op then return x
	bicw3	$0x7fff,8(%ap),%r2	# copy the sign bit of y into %r2
	bicw2	$0x8000,%r0		# replace x by |x|
	bisw2	%r2,%r0			# copy the sign bit of y to x
1:	ret
END(copysignf)

/*
 * float logbf(float x);
 */
ENTRY(logbf, 0)
	cvtfd   4(%ap),-(%sp)
	calls   $2,_C_LABEL(logb)
	cvtdf   %r0,%r0
	ret
END(logbf)

/*
 * double logb(double x);
 */
ENTRY(logb, 0)
	bicl3	$0xffff807f,4(%ap),%r0	# mask off the exponent of x
	beql    Ln
	ashl	$-7,%r0,%r0		# get the bias exponent
	subl2	$129,%r0			# get the unbias exponent
	cvtld	%r0,%r0			# return the answer in double
	ret
Ln:	movq	4(%ap),%r0		# %r0:1 = x (zero or reserved op)
	bneq	1f			# simply return if reserved op
	movq 	$0x0000fe00ffffcfff,%r0  # -2147483647.0
1:	ret
END(logb)

/*
 * long finite(double x);
 */
#ifndef __GFLOAT__
WEAK_ALIAS(finitef, _finitef)
STRONG_ALIAS(_finitef, _finite)
#endif
WEAK_ALIAS(finite, _finite)
ENTRY(_finite, 0)
	bicw3	$0x7f,4(%ap),%r0	# mask off the significand
	cmpw	%r0,$0x8000		# to see if x is the reserved op
	beql	1f			# if so, return FALSE (0)
	movl	$1,%r0			# else return TRUE (1)
	ret
1:	clrl	%r0
	ret
END(_finite)

/* int isnan(double x);
 */
#if 0
ENTRY(isnan, 0)
	clrl	%r0
	ret
#endif

/* int isnanf(float x);
 */
ENTRY(isnanf, 0)
	clrl	%r0
	ret
END(isnanf)

/*
 * double scalb(x,N)
 * double x; double N;
 */
	.set	ERANGE,34

ENTRY(scalb, 0)
	movq	4(%ap),%r0
	bicl3	$0xffff807f,%r0,%r3
	beql	ret1			# 0 or reserved operand
	movq	12(%ap),%r4
	cvtdl	%r4, %r2
	cmpl	%r2,$0x12c
	bgeq	ovfl
	cmpl	%r2,$-0x12c
	bleq	unfl
	ashl	$7,%r2,%r2
	addl2	%r2,%r3
	bleq	unfl
	cmpl	%r3,$0x8000
	bgeq	ovfl
	addl2	%r2,%r0
	ret
ovfl:	pushl	$ERANGE
	calls	$1,_C_LABEL(infnan)	# if it returns
	bicw3	$0x7fff,4(%ap),%r2	# get the sign of input arg
	bisw2	%r2,%r0			# re-attach the sign to %r0/1
	ret
unfl:	movq	$0,%r0
ret1:	ret
END(scalb)

/*
 * DREM(X,Y)
 * RETURN X REM Y =X-N*Y, N=[X/Y] ROUNDED (ROUNDED TO EVEN IN THE HALF WAY CASE)
 * DOUBLE PRECISION (VAX D format 56 bits)
 * CODED IN VAX ASSEMBLY LANGUAGE BY K.C. NG, 4/8/85.
 */
	.set	EDOM,33

ENTRY(drem, 0x0fc0)
	subl2	$12,%sp
	movq	4(%ap),%r0		#%r0=x
	movq	12(%ap),%r2		#%r2=y
	jeql	Rop			#if y=0 then generate reserved op fault
	bicw3	$0x007f,%r0,%r4		#check if x is Rop
	cmpw	%r4,$0x8000
	jeql	Ret			#if x is Rop then return Rop
	bicl3	$0x007f,%r2,%r4		#check if y is Rop
	cmpw	%r4,$0x8000
	jeql	Ret			#if y is Rop then return Rop
	bicw2	$0x8000,%r2		#y  := |y|
	movw	$0,-4(%fp)		#-4(%fp) = nx := 0
	cmpw	%r2,$0x1c80		#yexp ? 57
	bgtr	C1			#if yexp > 57 goto C1
	addw2	$0x1c80,%r2		#scale up y by 2**57
	movw	$0x1c80,-4(%fp)		#nx := 57 (exponent field)
C1:
	movw	-4(%fp),-8(%fp)		#-8(%fp) = nf := nx
	bicw3	$0x7fff,%r0,-12(%fp)	#-12(%fp) = sign of x
	bicw2	$0x8000,%r0		#x  := |x|
	movq	%r2,%r10			#y1 := y
	bicl2	$0xffff07ff,%r11		#clear the last 27 bits of y1
loop:
	cmpd	%r0,%r2			#x ? y
	bleq	E1			#if x <= y goto E1
 /* begin argument reduction */
	movq	%r2,%r4			#t =y
	movq	%r10,%r6			#t1=y1
	bicw3	$0x807f,%r0,%r8		#xexp= exponent of x
	bicw3	$0x807f,%r2,%r9		#yexp= exponent fo y
	subw2	%r9,%r8			#xexp-yexp
	subw2	$0x0c80,%r8		#k=xexp-yexp-25(exponent bit field)
	blss	C2			#if k<0 goto C2
	addw2	%r8,%r4			#t +=k
	addw2	%r8,%r6			#t1+=k, scale up t and t1
C2:
	divd3	%r4,%r0,%r8		#x/t
	cvtdl	%r8,%r8			#n=[x/t] truncated
	cvtld	%r8,%r8			#float(n)
	subd2	%r6,%r4			#t:=t-t1
	muld2	%r8,%r4			#n*(t-t1)
	muld2	%r8,%r6			#n*t1
	subd2	%r6,%r0			#x-n*t1
	subd2	%r4,%r0			#(x-n*t1)-n*(t-t1)
	jbr	loop
E1:
	movw	-4(%fp),%r6		#%r6=nx
	beql	C3			#if nx=0 goto C3
	addw2	%r6,%r0			#x:=x*2**57 scale up x by nx
	movw	$0,-4(%fp)		#clear nx
	jbr	loop
C3:
	movq	%r2,%r4			#%r4 = y
	subw2	$0x80,%r4		#%r4 = y/2
	cmpd	%r0,%r4			#x:y/2
	blss	E2			#if x < y/2 goto E2
	bgtr	C4			#if x > y/2 goto C4
	cvtdl	%r8,%r8			#ifix(float(n))
	blbc	%r8,E2			#if the last bit is zero, goto E2
C4:
	subd2	%r2,%r0			#x-y
E2:
	xorw2	-12(%fp),%r0		#x^sign (exclusive or)
	movw	-8(%fp),%r6		#%r6=nf
	bicw3	$0x807f,%r0,%r8		#%r8=exponent of x
	bicw2	$0x7f80,%r0		#clear the exponent of x
	subw2	%r6,%r8			#%r8=xexp-nf
	bgtr	C5			#if xexp-nf is positive goto C5
	movw	$0,%r8			#clear %r8
	movq	$0,%r0			#x underflow to zero
C5:
	bisw2	%r8,%r0			/* put %r8 into x's exponent field */
	ret
Rop:					#Reserved operand
	pushl	$EDOM
	calls	$1,_C_LABEL(infnan)	#generate reserved op fault
	ret
Ret:
	movq	$0x8000,%r0		#propagate reserved op
	ret
END(drem)
