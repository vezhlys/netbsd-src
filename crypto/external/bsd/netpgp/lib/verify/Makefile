# $NetBSD: Makefile,v 1.19 2025/04/06 23:03:04 rillig Exp $

LIB=netpgpverify
SRCS+=b64.c
SRCS+=bignum.c
SRCS+=bufgap.c
SRCS+=digest.c
SRCS+=libverify.c
SRCS+=misc.c
SRCS+=pgpsum.c
SRCS+=rsa.c
SRCS+=bzlib.c
SRCS+=zlib.c
SRCS+=sha1.c
SRCS+=sha2.c
SRCS+=md5c.c
SRCS+=rmd160.c
CPPFLAGS+=-I${.CURDIR} -I${EXTDIST}/src/netpgpverify
MAN=libnetpgpverify.3
WARNS=5

EXTDIST=${.CURDIR}/../../dist
.PATH: ${EXTDIST}/src/netpgpverify

INCS=verify.h
INCSDIR=/usr/include/netpgp

.include <bsd.own.mk>

COPTS+=			${CC_WNO_IMPLICIT_FALLTHROUGH}
COPTS.libverify.c+=	${CC_WNO_FORMAT_TRUNCATION}

LINTFLAGS.bzlib.c+=	-X 220	# fallthrough on case statement
LINTFLAGS.zlib.c+=	-X 220	# fallthrough on case statement

VERSION_MAP=		verify.map
LIB_EXPSYM=		verify.expsym

.include <bsd.lib.mk>
