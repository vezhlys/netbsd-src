#	$NetBSD: Makefile,v 1.61 2025/05/13 21:36:26 nia Exp $

# build libraries for xorg

.include <bsd.own.mk>

.include "mesa-which.mk"

SUBDIR=	libfontenc freetype libFS libICE libglapi${OLD_SUFFIX} \
	libXau libXdmcp libdrm libpciaccess \
	libxcvt libxshmfence .WAIT
.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "x86_64"
SUBDIR+=libdrm_intel
.endif
.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "x86_64" || ${MACHINE} == "evbarm"
SUBDIR+=libdrm_amdgpu libdrm_nouveau
.endif
SUBDIR+=libdrm_radeon pixman
.if !defined(MLIBDIR)
SUBDIR+=xkeyboard-config
.endif
SUBDIR+=libxcb \
	.WAIT \
	libX11 \
	.WAIT
.if !defined(MLIBDIR)
SUBDIR+=dri${OLD_SUFFIX} gallium${OLD_SUFFIX}
.endif
SUBDIR+=fontconfig libSM \
	.WAIT \
	libXcomposite libXdamage libXext libXfixes libXt \
	libxkbfile libepoxy \
	.WAIT
.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "x86_64" || ${MACHINE} == "evbarm"
# libvdpau depends upon libX11 and libXext
SUBDIR+=libvdpau \
	.WAIT
.endif
SUBDIR+=libXi libXxf86vm \
	libGL${OLD_SUFFIX} libXScrnSaver libXfont libXfont2 \
	libXinerama libXmu libXmuu libXpm libXrender \
	libXres libXtst libXvMC libXvMCW libXv libXxf86dga \
	libxkbui \
	.WAIT
.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "x86_64"
SUBDIR+=libI810XvMC
SUBDIR+=libIntelXvMC
SUBDIR+=libchromeXvMC
SUBDIR+=libchromeXvMCPro
.endif
SUBDIR+=libGLU libGLw libXaw6 libXaw libXcursor \
	libXrandr \
	.WAIT \
	libXpresent libXft \
	.WAIT \
	libXdmGreet \
	xcb-util
SUBDIR+=libgbm${OLD_SUFFIX}
.if ${HAVE_XORG_EGL} != "no"
# libEGL depends upon libgbm
SUBDIR+=.WAIT libEGL${OLD_SUFFIX}
.endif

.include <bsd.buildinstall.mk>
.include <bsd.subdir.mk>
