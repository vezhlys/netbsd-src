#	$NetBSD: Makefile,v 1.42 2024/05/17 20:27:09 christos Exp $

.include <bsd.own.mk>
.include "${NETBSDSRCDIR}/distrib/common/Makefile.distrib"
.include <bsd.kernobj.mk>

IMAGE=		ramdisk.fs
IMAGESIZE=	660k
IMAGESPECEXTRA=	dev/pipe
MAKEFS_FLAGS+=	-f 6 -o density=3500

WARNS=		1
DBG=		-Os

CRUNCHBIN=	rd_bin
LISTS=		${.CURDIR}/list
MTREECONF=	${.CURDIR}/mtree.conf
IMAGEENDIAN=	be
MAKEDEVTARGETS=	std md0 cd0 st0 st1 sd0 sd1 sd2 xd0 xy0 fd0
IMAGEDEPENDS=	${CRUNCHBIN} \
		fstab passwd protocols ${DISTRIBDIR}/common/services \
		sshrc welcome ${NETBSDSRCDIR}/etc/netconfig

MDSETTARGETS=		RAMDISK		ramdisk.fs	- \
			RAMDISK3X	ramdisk.fs	-
MDSET_RELEASEDIR=	binary/kernel

# Use stubs to eliminate some large stuff from libc
HACKSRC=	${DISTRIBDIR}/utils/libhack
.include	"${HACKSRC}/Makefile.inc"
${CRUNCHBIN}:	libhack.o

fstab: .PHONY

.include "${DISTRIBDIR}/common/Makefile.crunch"
.include "${DISTRIBDIR}/common/Makefile.makedev"
.include "${DISTRIBDIR}/common/Makefile.image"
.include "${DISTRIBDIR}/common/Makefile.mdset"

.include <bsd.prog.mk>
