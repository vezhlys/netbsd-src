# $NetBSD: Makefile,v 1.5 2018/05/01 19:59:42 christos Exp $

.include <bsd.hostinit.mk>
.include <${.CURDIR}/../../../Makefile.inc>

.PATH:	${HEIMDIST}/lib/com_err	\
	${HEIMDIST}/lib/roken	\
	${HEIMDIST}/lib/vers

PROG= compile_et

SRCS+=	compile_et.c parse.y lex.l \
	getarg.c print_version.c warnerr.c strupr.c get_window_size.c \
	rand.c

YHEADER=	# defined

BINDIR=		/usr/bin

LIBROKEN!=	cd ${HEIMBASE}/lib/libroken && ${PRINTOBJDIR}

CPPFLAGS+=				\
	 -I${HEIMDIST}/lib/roken

#	-I${DESTDIR}/usr/include	\

HOST_CPPFLAGS+= -I.			\
	-I${HEIMBASE}/include		\
	-I${HEIMBASE}/include/krb5	\
	-I${LIBROKEN}			\
	-I${HEIMDIST}/lib/com_err	\
	-I${HEIMDIST}/lib/roken		\
	-DKRB5=1			\
	-DHAVE_CONFIG_H

DPSRCS=		print_version.h

make-print-version.lo: ${HEIMBASE}/include/version.h

make-print-version: make-print-version.lo
	${HOST_CC} ${HOST_LDFLAGS} -o ${.TARGET} ${.ALLSRC}

print_version.h: make-print-version
	./make-print-version print_version.h

CLEANFILES+=	print_version.h make-print-version make-print-version.lo

beforedepend:
	[ -h krb5 ] || ln -sf . krb5
	ln -sf ${HEIMBASE}/include/roken.h
	ln -sf ${HEIMBASE}/include/krb5-types.h
	ln -sf ${HEIMBASE}/dist/lib/roken/roken-common.h
	ln -sf ${HEIMBASE}/dist/lib/roken/getarg.h

CLEANFILES+=	krb5 roken.h krb5-types.h roken-common.h getarg.h

.ifndef HOSTPROG
HOSTPROG=	${PROG}
.include <bsd.hostprog.mk>
.endif
