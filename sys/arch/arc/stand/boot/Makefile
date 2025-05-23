# $NetBSD: Makefile,v 1.19 2024/06/29 08:02:06 rin Exp $

.include <bsd.init.mk>

S!= cd ${.CURDIR}/../../../..; pwd

PROG= boot
MKMAN= no		# defined
STRIPFLAG=
BINMODE= 444

NETBSD_VERS!=	${HOST_SH} ${S}/conf/osrelease.sh

.PATH:		${S}/dev/arcbios

SRCS=	start.S arcbios_calls.S
SRCS+=	boot.c bootinfo.c conf.c devopen.c disk.c getchar.c putchar.c

.include "${S}/dev/arcbios/Makefile.inc"

# XXX SHOULD NOT NEED TO DEFINE THESE!
LIBCRT0=
LIBCRTI=
LIBC=
LIBCRTBEGIN=
LIBCRTEND=

AFLAGS=    -x assembler-with-cpp -mno-abicalls -mips2 -mabi=32
AFLAGS+=   -D_LOCORE -D_KERNEL
CFLAGS=    -Os -mmemcpy -G 1024
CFLAGS+=   -ffreestanding -mno-abicalls -msoft-float -mips2 -mabi=32
CFLAGS+=   -Werror -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CPPFLAGS+= -nostdinc -I. -I${S}
CPPFLAGS+= -D_STANDALONE -DNO_ABICALLS -D${MACHINE}
CPPFLAGS+= -DNETBSD_VERS='"${NETBSD_VERS}"'
#CPPFLAGS+= -DBOOT_DEBUG
LDSCRIPT=  ${S}/arch/mips/conf/stand.ldscript
TEXTADDR=  0x80f00000
LD+=		-m elf32ltsmip

### find out what to use for libsa
SAMISCMAKEFLAGS= SA_USE_CREAD=yes SA_USE_LOADFILE=yes
.include "${S}/lib/libsa/Makefile.inc"
LIBSA=   ${SALIB}

### find out what to use for libkern
.include "${S}/lib/libkern/Makefile.inc"
LIBKERN= ${KERNLIB}

### find out what to use for libz
.include "${S}/lib/libz/Makefile.inc"
LIBZ=    ${ZLIB}

LIBS=  ${LIBSA} ${LIBKERN} ${LIBZ}

cleandir distclean: .WAIT cleanlibdir
cleanlibdir:
	-rm -rf lib

${PROG}: ${OBJS} ${LIBS}
	${LD} -Map ${PROG}.map -N -x -Ttext ${TEXTADDR} -T ${LDSCRIPT} \
	    -e start -o ${PROG}.elf ${OBJS} ${LIBS}
	@${SIZE} ${PROG}.elf
	${OBJCOPY} --impure -O ecoff-littlemips \
	    -R .pdr -R .mdebug.abi32 -R .comment -R .ident --strip-debug \
	    ${PROG}.elf ${.TARGET}

CLEANFILES+=	${PROG}.elf ${PROG}.map

.include "${S}/conf/newvers_stand.mk"

.include <bsd.klinks.mk>
.include <bsd.prog.mk>
