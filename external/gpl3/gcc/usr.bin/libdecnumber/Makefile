#	$NetBSD: Makefile,v 1.11 2024/09/29 16:53:05 kalvisd Exp $

DIST=		${GCCDIST}
GNUHOSTDIST=	${DIST}

HOSTPROG_CXX=	1
LIBISPRIVATE=   yes

.include <bsd.init.mk>

LIB=		decnumber

SRCS=		decNumber.c decContext.c decimal32.c decimal64.c decimal128.c
CPPFLAGS+=	-I${.CURDIR}/arch/${GCC_MACHINE_ARCH} -I${DIST}/libdecnumber
CPPFLAGS+=	-I${DIST}/libgcc


.include <bsd.lib.mk>

# Force using C++ for this
HOST_CC:=	${HOST_CXX}
HOST_CFLAGS:=	${HOST_CXXFLAGS}
CC:=		${CXX}
CFLAGS:=	${CXXFLAGS}

.PATH: ${DIST}/libdecnumber ${DIST}/libdecnumber/dpd
