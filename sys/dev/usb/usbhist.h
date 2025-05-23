/*	$NetBSD: usbhist.h,v 1.9 2025/04/26 06:55:19 andvar Exp $	*/

/*
 * Copyright (c) 2012 Matthew R. Green
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _DEV_USB_USBHIST_H_
#define _DEV_USB_USBHIST_H_

#if defined(_KERNEL_OPT)
#include "opt_usb.h"
#endif

/*
 * Make USBHIST_PRINT force on KERNHIST_PRINT for at least USBHIST_* usage.
 */
#if defined(USBHIST_PRINT) && !defined(KERNHIST_PRINT)
#define KERNHIST_PRINT 1
#endif

#include <sys/kernhist.h>

#ifdef USB_DEBUG

extern int usbdebug;

#define USBHIST_DECL(NAME)		KERNHIST_DECL(NAME)
#define USBHIST_DEFINE(NAME)		KERNHIST_DEFINE(NAME)
#define USBHIST_INIT(NAME,N)		KERNHIST_INIT(NAME,N)
#define USBHIST_LINK_STATIC(NAME)	KERNHIST_LINK_STATIC(NAME)
#define USBHIST_LOGN(NAME,N,FMT,A,B,C,D)	do {		\
	if ((NAME) >= (N)) {					\
		KERNHIST_LOG(usbhist,FMT,A,B,C,D);		\
	}							\
} while (0)
#define USBHIST_LOGM(NAME,N,FMT,A,B,C,D)	do {		\
	if ((NAME) & (N)) {					\
		KERNHIST_LOG(usbhist,FMT,A,B,C,D);		\
	}							\
} while (0)
#define USBHIST_LOG(NAME,FMT,A,B,C,D)	USBHIST_LOGN(NAME,1,FMT,A,B,C,D)
#define USBHIST_CALLED(NAME)			do {		\
	if ((NAME) != 0) {					\
		KERNHIST_CALLED(usbhist);			\
	}							\
} while (0)
#define USBHIST_CALLARGS(NAME,FMT,A,B,C,D) do {			\
	if ((NAME) != 0) {					\
		KERNHIST_CALLARGS(usbhist,FMT,A,B,C,D);		\
	}							\
} while (0)
#define USBHIST_CALLARGSN(NAME,N,FMT,A,B,C,D) do {		\
	if ((NAME) >= (N)) {					\
		KERNHIST_CALLARGS(usbhist,FMT,A,B,C,D);		\
	}							\
} while (0)
#define USBHIST_FUNC()			KERNHIST_FUNC(__func__)

USBHIST_DECL(usbhist);

#else

#define USBHIST_DECL(NAME)
#define USBHIST_DEFINE(NAME)
#define USBHIST_INIT(NAME,N)
#define USBHIST_LINK_STATIC(NAME)
#define USBHIST_LOGN(N,NAME,FMT,A,B,C,D)	do { } while(0)
#define USBHIST_LOGM(N,NAME,FMT,A,B,C,D)	do { } while(0)
#define USBHIST_LOG(NAME,FMT,A,B,C,D)		do { } while(0)
#define USBHIST_CALLARGS(NAME,FMT,A,B,C,D)
#define USBHIST_CALLARGSN(NAME,N,FMT,A,B,C,D)
#define USBHIST_CALLED(NAME)
#define USBHIST_FUNC()

#endif

#endif /* _DEV_USB_USBHIST_H_ */
