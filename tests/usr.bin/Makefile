#	$NetBSD: Makefile,v 1.43 2025/01/18 22:31:22 rillig Exp $
#

.include <bsd.own.mk>

TESTSDIR=       ${TESTSBASE}/usr.bin

TESTS_SUBDIRS=	awk basename bzip2 cc cmp compress config cpio col cut \
		diff dirname error find fstat ftp gcov gdb grep gzip id indent \
		infocmp jot ld locale m4 make mixerctl mkdep mtree nbperf \
		netpgpverify patch pkill pr printf pwhash realpath rump_server \
		shmif_dumpbus shmif_pcapin sdiff sed sort stat tar tmux tr \
		unifdef uniq vmstat xlint ztest

.if ${MKCXX} != "no"
TESTS_SUBDIRS+=	c++
.endif

.include <bsd.test.mk>
