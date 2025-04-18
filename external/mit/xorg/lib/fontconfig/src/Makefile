#	$NetBSD: Makefile,v 1.30 2024/07/21 08:04:05 rillig Exp $

.include <bsd.own.mk>

LIB=	fontconfig

.PATH:	${X11SRCDIR.${LIB}}/src
SRCS=	fcatomic.c \
	fccache.c \
	fccfg.c \
	fccharset.c \
	fccompat.c \
	fcdbg.c \
	fcdefault.c \
	fcdir.c \
	fcformat.c \
	fcfreetype.c \
	fcfs.c \
	fchash.c \
	fcinit.c \
	fclang.c \
	fclist.c \
	fcmatch.c \
	fcmatrix.c \
	fcname.c \
	fcobjs.c \
	fcpat.c \
	fcptrlist.c \
	fcrange.c \
	fcserialize.c \
	fcstat.c \
	fcstr.c \
	fcweight.c \
	fcxml.c \
	ftglue.c

.PATH:	${X11SRCDIR.${LIB}}/doc
MAN=	\
	FcAtomicCreate.3 \
	FcAtomicDeleteNew.3 \
	FcAtomicDestroy.3 \
	FcAtomicLock.3 \
	FcAtomicNewFile.3 \
	FcAtomicOrigFile.3 \
	FcAtomicReplaceOrig.3 \
	FcAtomicUnlock.3 \
	FcBlanksAdd.3 \
	FcBlanksCreate.3 \
	FcBlanksDestroy.3 \
	FcBlanksIsMember.3 \
	FcCacheCopySet.3 \
	FcCacheCreateTagFile.3 \
	FcCacheDir.3 \
	FcCacheNumFont.3 \
	FcCacheNumSubdir.3 \
	FcCacheSubdir.3 \
	FcCharSetAddChar.3 \
	FcCharSetCopy.3 \
	FcCharSetCount.3 \
	FcCharSetCoverage.3 \
	FcCharSetCreate.3 \
	FcCharSetDelChar.3 \
	FcCharSetDestroy.3 \
	FcCharSetEqual.3 \
	FcCharSetFirstPage.3 \
	FcCharSetHasChar.3 \
	FcCharSetIntersect.3 \
	FcCharSetIntersectCount.3 \
	FcCharSetIsSubset.3 \
	FcCharSetMerge.3 \
	FcCharSetNew.3 \
	FcCharSetNextPage.3 \
	FcCharSetSubtract.3 \
	FcCharSetSubtractCount.3 \
	FcCharSetUnion.3 \
	FcConfigAppFontAddDir.3 \
	FcConfigAppFontAddFile.3 \
	FcConfigAppFontClear.3 \
	FcConfigBuildFonts.3 \
	FcConfigCreate.3 \
	FcConfigDestroy.3 \
	FcConfigEnableHome.3 \
	FcConfigFileInfoIterGet.3 \
	FcConfigFileInfoIterInit.3 \
	FcConfigFileInfoIterNext.3 \
	FcConfigFilename.3 \
	FcConfigGetBlanks.3 \
	FcConfigGetCache.3 \
	FcConfigGetCacheDirs.3 \
	FcConfigGetConfigDirs.3 \
	FcConfigGetConfigFiles.3 \
	FcConfigGetCurrent.3 \
	FcConfigGetFontDirs.3 \
	FcConfigGetFonts.3 \
	FcConfigGetRescanInterval.3 \
	FcConfigGetSysRoot.3 \
	FcConfigHome.3 \
	FcConfigParseAndLoad.3 \
	FcConfigParseAndLoadFromMemory.3 \
	FcConfigReference.3 \
	FcConfigSetCurrent.3 \
	FcConfigSetRescanInterval.3 \
	FcConfigSetSysRoot.3 \
	FcConfigSubstitute.3 \
	FcConfigSubstituteWithPat.3 \
	FcConfigUptoDate.3 \
	FcDefaultSubstitute.3 \
	FcDirCacheClean.3 \
	FcDirCacheCreateUUID.3 \
	FcDirCacheDeleteUUID.3 \
	FcDirCacheLoad.3 \
	FcDirCacheLoadFile.3 \
	FcDirCacheRead.3 \
	FcDirCacheRescan.3 \
	FcDirCacheUnlink.3 \
	FcDirCacheUnload.3 \
	FcDirCacheValid.3 \
	FcDirSave.3 \
	FcDirScan.3 \
	FcFileIsDir.3 \
	FcFileScan.3 \
	FcFini.3 \
	FcFontList.3 \
	FcFontMatch.3 \
	FcFontRenderPrepare.3 \
	FcFontSetAdd.3 \
	FcFontSetCreate.3 \
	FcFontSetDestroy.3 \
	FcFontSetList.3 \
	FcFontSetMatch.3 \
	FcFontSetPrint.3 \
	FcFontSetSort.3 \
	FcFontSetSortDestroy.3 \
	FcFontSort.3 \
	FcFreeTypeCharIndex.3 \
	FcFreeTypeCharSet.3 \
	FcFreeTypeCharSetAndSpacing.3 \
	FcFreeTypeQuery.3 \
	FcFreeTypeQueryAll.3 \
	FcFreeTypeQueryFace.3 \
	FcGetDefaultLangs.3 \
	FcGetLangs.3 \
	FcGetVersion.3 \
	FcInit.3 \
	FcInitBringUptoDate.3 \
	FcInitLoadConfig.3 \
	FcInitLoadConfigAndFonts.3 \
	FcInitReinitialize.3 \
	FcIsLower.3 \
	FcIsUpper.3 \
	FcLangGetCharSet.3 \
	FcLangNormalize.3 \
	FcLangSetAdd.3 \
	FcLangSetCompare.3 \
	FcLangSetContains.3 \
	FcLangSetCopy.3 \
	FcLangSetCreate.3 \
	FcLangSetDel.3 \
	FcLangSetDestroy.3 \
	FcLangSetEqual.3 \
	FcLangSetGetLangs.3 \
	FcLangSetHasLang.3 \
	FcLangSetHash.3 \
	FcLangSetSubtract.3 \
	FcLangSetUnion.3 \
	FcMatrixCopy.3 \
	FcMatrixEqual.3 \
	FcMatrixInit.3 \
	FcMatrixMultiply.3 \
	FcMatrixRotate.3 \
	FcMatrixScale.3 \
	FcMatrixShear.3 \
	FcNameConstant.3 \
	FcNameGetConstant.3 \
	FcNameGetObjectType.3 \
	FcNameParse.3 \
	FcNameRegisterConstants.3 \
	FcNameRegisterObjectTypes.3 \
	FcNameUnparse.3 \
	FcNameUnregisterConstants.3 \
	FcNameUnregisterObjectTypes.3 \
	FcObjectSetAdd.3 \
	FcObjectSetBuild.3 \
	FcObjectSetCreate.3 \
	FcObjectSetDestroy.3 \
	FcPatternAdd-Type.3 \
	FcPatternAdd.3 \
	FcPatternAddWeak.3 \
	FcPatternBuild.3 \
	FcPatternCreate.3 \
	FcPatternDel.3 \
	FcPatternDestroy.3 \
	FcPatternDuplicate.3 \
	FcPatternEqual.3 \
	FcPatternEqualSubset.3 \
	FcPatternFilter.3 \
	FcPatternFindIter.3 \
	FcPatternFormat.3 \
	FcPatternGet-Type.3 \
	FcPatternGet.3 \
	FcPatternGetWithBinding.3 \
	FcPatternHash.3 \
	FcPatternIterEqual.3 \
	FcPatternIterGetObject.3 \
	FcPatternIterGetValue.3 \
	FcPatternIterIsValid.3 \
	FcPatternIterNext.3 \
	FcPatternIterStart.3 \
	FcPatternIterValueCount.3 \
	FcPatternObjectCount.3 \
	FcPatternPrint.3 \
	FcPatternReference.3 \
	FcPatternRemove.3 \
	FcRangeCopy.3 \
	FcRangeCreateDouble.3 \
	FcRangeCreateInteger.3 \
	FcRangeDestroy.3 \
	FcRangeGetDouble.3 \
	FcStrBasename.3 \
	FcStrCmp.3 \
	FcStrCmpIgnoreCase.3 \
	FcStrCopy.3 \
	FcStrCopyFilename.3 \
	FcStrDirname.3 \
	FcStrDowncase.3 \
	FcStrFree.3 \
	FcStrListCreate.3 \
	FcStrListDone.3 \
	FcStrListFirst.3 \
	FcStrListNext.3 \
	FcStrPlus.3 \
	FcStrSetAdd.3 \
	FcStrSetAddFilename.3 \
	FcStrSetCreate.3 \
	FcStrSetDel.3 \
	FcStrSetDestroy.3 \
	FcStrSetEqual.3 \
	FcStrSetMember.3 \
	FcStrStr.3 \
	FcStrStrIgnoreCase.3 \
	FcToLower.3 \
	FcUcs4ToUtf8.3 \
	FcUtf16Len.3 \
	FcUtf16ToUcs4.3 \
	FcUtf8Len.3 \
	FcUtf8ToUcs4.3 \
	FcValueDestroy.3 \
	FcValueEqual.3 \
	FcValuePrint.3 \
	FcValueSave.3 \
	FcWeightFromOpenType.3 \
	FcWeightFromOpenTypeDouble.3 \
	FcWeightToOpenType.3 \
	FcWeightToOpenTypeDouble.3

MAN+=	fonts-conf.5

MLINKS= fonts-conf.5 fonts.conf.5

LIBDPLIBS=\
	expat		${NETBSDSRCDIR}/external/mit/expat/lib/libexpat \
	freetype	${.CURDIR}/../../freetype

# XXX FONTCONFIG_PATH was arbitrarily chosen
FONTCONFIG_PATH=/etc/fonts
TEMPLATEDIR=${FONTCONFIG_PATH}/fontconfig/conf.avail

CPPFLAGS+=	-DHAVE_CONFIG_H
CPPFLAGS+=	-DFONTCONFIG_PATH='"${FONTCONFIG_PATH}"' \
		-DFC_DEFAULT_FONTS='"<dir>${X11FONTDIR}</dir>"' \
		-DFC_TEMPLATEDIR='"${X11FONTDIR}"' \
		-DFC_CACHEDIR='"/var/cache/fontconfig"' \
		-DCONFIGDIR='"${FONTCONFIG_PATH}/conf.d"' \
		-DHAVE_FT_BITMAP_SIZE_Y_PPEM \
		-DHAVE_FT_GET_BDF_PROPERTY \
		-DHAVE_FT_GET_NEXT_CHAR \
		-DHAVE_FT_GET_PS_FONT_INFO \
		-DHAVE_FT_GET_X11_FONT_FORMAT \
		-DHAVE_FT_HAS_PS_GLYPH_NAMES \
		-DHAVE_EXPAT -DXFREE86_FT2 -DHAVE_INTTYPES_H \
		-DHAVE_STDINT_H -DHAVE_RANDOM \
		-DHAVE_STRUCT_STAT_ST_MTIM \
		-DHAVE_FT_DONE_MM_VAR

CPPFLAGS+=	${X11FLAGS.THREADLIB}
CPPFLAGS+=	-I${DESTDIR}${X11INCDIR}/freetype2 \
		-I${X11SRCDIR.freetype}/src \
		-I${X11SRCDIR.freetype}/include \
		-I${X11SRCDIR.freetype}/include/freetype \
		-I${X11SRCDIR.${LIB}}/../include \
		-I. \
		-I${X11SRCDIR.${LIB}}

IGNORE_QUALIFIERS+= ${${ACTIVE_CC} == "gcc":? -Wno-error=discarded-qualifiers :}
IGNORE_QUALIFIERS+= ${${ACTIVE_CC} == "clang":? -Wno-error=incompatible-pointer-types-discards-qualifiers :}

CPPFLAGS.fccache.c+= 	${IGNORE_QUALIFIERS}
CPPFLAGS.fccfg.c+=	${IGNORE_QUALIFIERS}

.if ${MACHINE_ARCH:Mvax}
COPTS.fccache.c+=	-O0
COPTS.fccfg.c+=	-O0
.endif

.include "Makefile.fcarch"

CLEANFILES+= fcarch.h

PKGCONFIG=	fontconfig
PKGCONFIG_SED_FLAGS= \
	-e "s,@sysconfdir@,${X11ETCDIR},; \
	    s,@localstatedir@,/var,; \
	    s,@BASECONFIGDIR@,${FONTCONFIG_PATH},; \
	    s,@PKG_EXPAT_LIBS@,-lexpat,; \
	    s,@PKG_EXPAT_CFLAGS@,,; \
	    s,@TEMPLATEDIR@,${TEMPLATEDIR},; \
	    s,@fc_cachedir@,${FONTCONFIG_PATH},"

# XXX
CPPFLAGS.fcxml.c=	-Wno-error

CWARNFLAGS.clang+=	-Wno-pointer-sign -Wno-switch

.if ${MACHINE_ARCH} == "sparc" || ${COMMON_MACHINE_ARCH:U} == "sparc"
COPTS.fccache.c+=	${${ACTIVE_CC} == "clang":? -Wa,-Av8plus  :}
COPTS.fccfg.c+=	${${ACTIVE_CC} == "clang":? -Wa,-Av8plus  :}
COPTS.fccharset.c+=	${${ACTIVE_CC} == "clang":? -Wa,-Av8plus  :}
COPTS.fcobjs.c+=	${${ACTIVE_CC} == "clang":? -Wa,-Av8plus  :}
COPTS.fcpat.c+=	${${ACTIVE_CC} == "clang":? -Wa,-Av8plus  :}
COPTS.fcstr.c+=	${${ACTIVE_CC} == "clang":? -Wa,-Av8plus  :}
.endif

LINTFLAGS+=-DFC_NO_MT
LINTFLAGS.fclang.c+=	-X 141	# 'a - b' overflows 'unsigned long'

LIBUUID_DIST=	${NETBSDSRCDIR}/external/bsd/libuuid_ul/lib/libuuid_ul
.include "${LIBUUID_DIST}/srcs.mk"
.include "${LIBUUID_DIST}/libuuid_ul-rename.mk"
SRCS+=	${UUID_UL_SRCS}

includes depend dependall all: uuid/uuid.h
uuid/uuid.h:
	@-mkdir -p uuid
	ln -s ${X11SRCDIR}/external/bsd/libuuid_ul/dist/uuid.h uuid/uuid.h

CLEANFILES+=	uuid/uuid.h

.include <bsd.x11.mk>
.include <bsd.lib.mk>
