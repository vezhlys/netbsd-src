#	$NetBSD: Makefile.inc,v 1.17 2024/03/20 13:51:35 riastradh Exp $
#
#	etc.amd64/Makefile.inc -- amd64-specific etc Makefile targets
#

# If you change the list of distributed kernels, don't forget
# to update the release documentation in distrib/notes/common/contents

KERNEL_SETS=		GENERIC
KERNEL_SETS+=		GENERIC_KASLR
KERNEL_SETS+=		XEN3_DOM0 XEN3_DOMU
# KERNEL_SETS+=		GENERIC_USERMODE

BUILD_KERNELS=		INSTALL INSTALL_XEN3_DOMU

INSTALLATION_DIRS+= 	installation/cdrom
INSTALLATION_DIRS+= 	installation/misc
INSTALLATION_DIRS+= 	installation/miniroot
INSTALLATION_DIRS+= 	installation/ramdisk

snap_md_post:
	cd ${KERNSRCDIR}/arch/i386/stand/pxeboot && ${MAKE} release
	${MAKESUMS} -t ${RELEASEDIR}/${RELEASEMACHINEDIR}/installation/cdrom '*.iso'
	${MAKESUMS} -t ${RELEASEDIR}/${RELEASEMACHINEDIR}/installation/miniroot '*.*'
	${MAKESUMS} -t ${RELEASEDIR}/${RELEASEMACHINEDIR}/installation/misc '*.*'
	${MAKESUMS} -t ${RELEASEDIR}/${RELEASEMACHINEDIR}/installation/ramdisk '*.*'
