#	$NetBSD: Makefile,v 1.27 2025/05/09 18:44:06 martin Exp $

WARNS		?= 1
NOMAN		=
NOPIE		=

BINMODE		= 444

S		= ${.CURDIR}/../../../..
COMMON		= ${.CURDIR}/../common

LIBSADIR	= ${S}/lib/libsa
SYSVBFSDIR	= ${S}/fs/sysvbfs
EWS4800MIPSDIR	= ${.CURDIR}/../../ews4800mips
DEVDIR		= ${.CURDIR}/../../dev

# XXX SHOULD NOT NEED TO DEFINE THESE!
LIBCRT0=
LIBCRTI=
LIBC=
LIBCRTBEGIN=
LIBCRTEND=

.PATH:		${COMMON} ${LIBSADIR} ${SYSVBFSDIR}	\
		${EWS4800MIPSDIR} ${SBDDIR} ${DEVDIR}

COFFHDRFIX	= ${.OBJDIR}/coffhdrfix

PROG		= boot
BOOT_KERNEL	= boot_kernel
FILES		+= ${PROG}.coff ${BOOT_KERNEL}.gz # XXX hack to install these
SRCS		= start.S boot.c prompt.c delay.c cmd.c loader.c
SRCS		+= bfs_subr.o disk.c diskutil.c
SRCS		+= devopen.c datafs.c bootfs.c ustarfs.c
SRCS		+= lance.c ether_if.c
SRCS		+= device_test.c cop0.c mem.c
SRCS		+= boot_device.c floppy_2d.c floppy_2hd_ibmpc.c
#SRCS		+= floppy_2hc.c
SRCS		+= console.c cons_rom.c cons_fb.c cons_zskbd.c cons_zs.c
BINKERNEL_C	= ${COMMON}/binkernel.c
BINKERNEL_SIZE	= 2158592	# '2 * 1024 * 1024 + 60 * 1024'
BINKERNEL_O	= binkernel.o
BINKERNEL_DUMMY_O= binkernel_dummy.o

# ${S}/lib/libsa
SRCS		+= dev_net.c
# ${S}/fs/sysvbfs
SRCS		+= bfs.c
# ../../dev
SRCS		+= ga.c
# ../../ews4800mips
SRCS		+= pdinfo.c vtoc.c

.include "${S}/conf/newvers_stand.mk"

TEXTADDR	= 0xa0a00000
LINKFLAGS	= -T ${S}/arch/mips/conf/stand.ldscript -Ttext ${TEXTADDR} \
		  -e start -N
COFFLDFLAGS	= -T ${COMMON}/coffboot.ldscript -N

MIPSFLAGS	= -mips1 -G 0 -mno-abicalls
DEBUGFLAGS	= -Wall -Werror
DEBUGFLAGS	+= -Wmissing-prototypes -Wstrict-prototypes -Wpointer-arith
DEBUGFLAGS	+= -Wno-format-zero-length -Wno-sign-compare
OPTFLAGS	= -Os -mmemcpy -fno-unwind-tables
FLAGS		= ${MIPSFLAGS} ${DEBUGFLAGS} ${OPTFLAGS}
AFLAGS		= -xassembler-with-cpp -D_LOCORE ${FLAGS}
CFLAGS		= ${FLAGS} -ffreestanding

CPPFLAGS	+= -D_STANDALONE -DSUPPORT_BOOTP
CPPFLAGS	+= -nostdinc -I${.OBJDIR} -I${.CURDIR} -I${COMMON} -I${S}
CPPFLAGS	+= -D__daddr_t=int32_t
#CPPFLAGS	+= -DBOOTP_DEBUG -DNETIF_DEBUG -DETHER_DEBUG -DNFS_DEBUG
#CPPFLAGS	+= -DRPC_DEBUG -DRARP_DEBUG -DNET_DEBUG -DDEBUG -DPARANOID

CLEANFILES	+= ${BINKERNEL_DUMMY_O} ${BINKERNEL_O}
CLEANFILES	+= ${PROG} ${PROG}.elf ${PROG}.coff ${PROG}.tmp ${PROG}.dis
CLEANFILES	+= ${COFFHDRFIX}
CLEANFILES	+= ${BOOT_KERNEL} ${BOOT_KERNEL}.elf ${BOOT_KERNEL}.tmp
CLEANFILES	+= ${BOOT_KERNEL}.gz ${BOOT_KERNEL}.gz.tmp

.include "${S}/lib/libkern/Makefile.inc"
LIBKERN=	${KERNLIB}

.include "${S}/lib/libz/Makefile.inc"
LIBZ=		${ZLIB}

CPPFLAGS+= -DLIBSA_ENABLE_LS_OP
SAMISCMAKEFLAGS= SA_USE_CREAD=yes SA_USE_LOADFILE=yes SA_ENABLE_LS_OP=yes
.include "${S}/lib/libsa/Makefile.inc"
LIBSA=		${SALIB}

LIBS		= ${LIBSA} ${LIBZ} ${LIBKERN}

# fixup GNU binutils file offset error.
coffhdrfix:	${COMMON}/coffhdrfix.c
	${HOST_CC} -o ${COFFHDRFIX} ${COMMON}/coffhdrfix.c

cleandir distclean: .WAIT cleanlibdir

cleanlibdir:
	-rm -rf lib

${BINKERNEL_DUMMY_O}: ${BINKERNEL_C}
	${_MKTARGET_COMPILE}
	${COMPILE.c} -DKERNEL_SIZE=0 ${BINKERNEL_C} -o ${.TARGET}

${BINKERNEL_O}: ${BINKERNEL_C}
	${_MKTARGET_COMPILE}
	${COMPILE.c} -DKERNEL_SIZE=${BINKERNEL_SIZE} ${BINKERNEL_C} \
	    -o ${.TARGET}

all realall: ${PROG}.coff ${BOOT_KERNEL}.gz

${PROG}: ${BINKERNEL_DUMMY_O} ${OBJS} ${LIBS}
	${_MKTARGET_LINK}
	${LD} ${LINKFLAGS} -S -o ${PROG}.elf ${OBJS} ${LIBS} \
	    ${BINKERNEL_DUMMY_O}
	${OBJDUMP} -h ${PROG}.elf
#	${OBJDUMP} -m mips:4000 -d ${PROG}.elf > ${PROG}.dis
	mv ${PROG}.elf ${PROG}
	ls -al ${PROG}

.include <bsd.klinks.mk>
.include <bsd.prog.mk>

${PROG}.coff:	${PROG}
	${_MKTARGET_CREATE}
	${MIPS_ELF2ECOFF} ${PROG} ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

${BOOT_KERNEL}.gz: ${BINKERNEL_O} ${OBJS} ${LIBS}
	${_MKTARGET_LINK}
	${LD} ${LINKFLAGS} -o ${BOOT_KERNEL}.elf ${OBJS} ${LIBS} \
	    ${BINKERNEL_O}
	mv ${BOOT_KERNEL}.elf ${BOOT_KERNEL}
	${OBJDUMP} -h ${BOOT_KERNEL}
	${TOOL_GZIP_N} -9c ${BOOT_KERNEL} > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
	ls -al ${.TARGET}

COPTS.ustarfs.c+=	-fno-strict-aliasing
