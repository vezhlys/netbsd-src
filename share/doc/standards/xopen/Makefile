#	$NetBSD: Makefile,v 1.6 2024/04/05 23:06:32 christos Exp $

DOCS=	xcu5
.for i in ${DOCS}
TARGS+=	${i}.ps ${i}.txt ${i}.html ${i}.more
.endfor

POST_PLAIN= -P-b -P-u -P-o -Tascii

ARGS_PS=	${GFLAGS} -dformat=PostScript ${ROFF_PAGESIZE}
ARGS_TXT=	${GFLAGS} -dformat=ASCII ${POST_PLAIN}
ARGS_HTML=	${GFLAGS} -dformat=HTML  ${POST_PLAIN} -ww
ARGS_MORE=	${GFLAGS} -dformat=more -P-h -Tascii

CLEANFILES+=${TARGS}

all: ${TARGS}

.for i in ${DOCS}
${i}.ps: ${i}
	${TOOL_GROFF} ${ARGS_PS}   -mdoc      ${.ALLSRC} > $@

${i}.txt: ${i}
	${TOOL_GROFF} ${ARGS_TXT}  -mdoc      ${.ALLSRC} > $@

${i}.html: ${i}
	${TOOL_GROFF} ${ARGS_HTML} -mdoc2html ${.ALLSRC} > $@

${i}.more: ${i}
	${TOOL_GROFF} ${ARGS_MORE} -mdoc      ${.ALLSRC} > $@
.endfor

echosrcs! ${SRCS}
	@echo ${.ALLSRC}

echomore!
	@echo ${.OBJDIR}/${TARG}.more

.include <bsd.doc.mk>
