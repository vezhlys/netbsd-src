# $NetBSD: t_vnd.sh,v 1.16 2025/04/19 02:07:43 rin Exp $
#
# Copyright (c) 2006, 2007, 2008 The NetBSD Foundation, Inc.
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

#
# Verifies that vnd works with files stored in tmpfs.
#

vnddev=vnd3
rvnd=/dev/r${vnddev}a
vnd=/dev/${vnddev}a

atf_test_case basic cleanup
basic_head() {
	atf_set "descr" "Verifies that vnd works with files stored in tmpfs"
	atf_set "require.user" "root"
}
basic_body() {
	if [ $(uname -p) = vax ]; then
		atf_skip "port-vax/59287 vnd(4) can cause kernel crash"
	fi

	test_mount

	atf_check -s exit:0 -o ignore -e ignore \
	    dd if=/dev/zero of=disk.img bs=1m count=10
	atf_check -s exit:0 -o empty -e empty vndconfig -c ${vnddev} disk.img

	atf_check -s exit:0 -o ignore -e ignore disklabel -i -I ${vnddev} << EOF
a
4.2BSD
0
$
W
y
Q
EOF
	atf_check -s exit:0 -o ignore -e ignore newfs -I ${rvnd}


	atf_check -s exit:0 -o empty -e empty mkdir mnt
	atf_check -s exit:0 -o empty -e empty mount ${vnd} mnt

	echo "Creating test files"
	for f in $(jot -w %u 100 | uniq); do
		jot 1000 >mnt/${f} || atf_fail "Failed to create file ${f}"
	done

	echo "Verifying created files"
	for f in $(jot -w %u 100 | uniq); do
		[ $(md5 mnt/${f} | cut -d ' ' -f 4) = \
		    53d025127ae99ab79e8502aae2d9bea6 ] || \
		    atf_fail "Invalid checksum for file ${f}"
	done

	atf_check -s exit:0 -o empty -e empty umount mnt
	atf_check -s exit:0 -o empty -e empty vndconfig -u ${vnddev}

	test_unmount
	touch done
}
basic_cleanup() {
	if [ ! -f done ]; then
		umount mntpt/mnt 2>/dev/null 1>&2
		vndconfig -u ${vnddev} 2>/dev/null 1>&2
	fi
}

atf_init_test_cases() {
	. $(atf_get_srcdir)/../h_funcs.subr
	. $(atf_get_srcdir)/h_funcs.subr

	atf_add_test_case basic
}
