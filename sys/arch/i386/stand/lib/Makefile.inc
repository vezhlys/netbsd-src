#	$NetBSD: Makefile.inc,v 1.21 2025/05/25 20:02:04 rillig Exp $
#
#	Configuration variables (default values are below):
#
#	S	must be set to the top of the 'sys' tree.
#	I386DST	may be set to the location of the directory where library
#		objects are to be built.  Defaults to ${.OBJDIR}/lib/i386.
#	I386MISCCPPFLAGS
#		Miscellaneous cpp flags to be passed to the library's Makefile
#		when building.
#	I386MISCMAKEFLAGS
#		Miscellaneous flags to be passed to the library's Makefile when
#		building.  See library's Makefile for more details about
#		supported flags and their default values.

# Default values:
I386DST?=		${.OBJDIR}/lib/i386

#I386DIR=		$S/arch/i386/stand/lib
I386LIB=		${I386DST}/libi386.a

CWARNFLAGS.clang+=	-Wno-tautological-compare

I386MAKE= \
	cd ${I386DIR} && MAKEOBJDIRPREFIX= && unset MAKEOBJDIRPREFIX && \
	    MAKEOBJDIR=${I386DST} ${MAKE} \
	    CC=${CC:q} CFLAGS=${CFLAGS:q} \
	    AS=${AS:q} AFLAGS=${AFLAGS:q} \
	    COPTS=${COPTS:q} \
	    LD=${LD:q} STRIP=${STRIP:q} \
	    MACHINE=${MACHINE} MACHINE_ARCH=${MACHINE_ARCH:q} \
	    I386CPPFLAGS=${CPPFLAGS:S@^-I.@-I../../.@g:q} \
	    I386MISCCPPFLAGS=${I386MISCCPPFLAGS:q} \
	    ${I386MISCMAKEFLAGS}

${I386LIB}:		.NOTMAIN __always_make_i386lib
	@echo making sure the i386 library is up to date...
	@${:D make}${I386MAKE} libi386.a

clean:			.NOTMAIN cleani386lib
cleani386lib:		.NOTMAIN
	@echo cleaning the i386 library objects
	@${:D make}if [ -d "${I386DST}" ]; then ${I386MAKE} clean; fi

cleandir distclean:	.NOTMAIN cleandiri386lib
cleandiri386lib:	.NOTMAIN
	@echo cleandiring the i386 library objects
	@${:D make}if [ -d "${I386DST}" ]; then ${I386MAKE} cleandir; fi

dependall depend:	.NOTMAIN dependi386lib
dependi386lib:		.NOTMAIN __always_make_i386lib
	@echo depending the i386 library objects
	@${:D make}${I386MAKE} depend

__always_make_i386lib:	.NOTMAIN
	@mkdir -p ${I386DST}
