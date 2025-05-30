#       $NetBSD: t_tcpip.sh,v 1.26 2025/04/25 22:51:29 riastradh Exp $
#
# Copyright (c) 2011 The NetBSD Foundation, Inc.
# All rights reserved.
#
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

rumpnetsrv="rump_server -lrumpnet -lrumpnet_net -lrumpnet_netinet"
export RUMP_SERVER=unix://csock

atf_test_case http cleanup
http_head()
{
        atf_set "descr" "Start hijacked httpd and get webpage from it"
}

http_body()
{

	atf_check -s exit:0 ${rumpnetsrv} -lrumpnet_netinet6 ${RUMP_SERVER}

	# start bozo in daemon mode
	atf_check -s exit:0 env LD_PRELOAD=/usr/lib/librumphijack.so \
	    /usr/libexec/httpd -P ./httpd.pid -b -s $(atf_get_srcdir)

	atf_check -s exit:0 -o file:"$(atf_get_srcdir)/netstat.expout" \
	    rump.netstat -a

	# get the webpage
	atf_check -s exit:0 env LD_PRELOAD=/usr/lib/librumphijack.so 	\
	    $(atf_get_srcdir)/h_netget 127.0.0.1 80 webfile

	# check that we got what we wanted
	atf_check -o match:'HTTP/1.0 200 OK' cat webfile
	atf_check -o match:'Content-Length: 95' cat webfile
	blank_line_re="$(printf '^\r$')" # matches a line with only <CR><LF>
	atf_check -o file:"$(atf_get_srcdir)/index.html" \
	    sed -n "1,/${blank_line_re}/!p" webfile
}

http_cleanup()
{
	if [ -f httpd.pid ]; then
		kill -9 "$(cat httpd.pid)"
		rm -f httpd.pid
	fi

	rump.halt
}

#
# Starts a SSH server and sets up the client to access it.
# Authentication is allowed and done using an RSA key exclusively, which
# is generated on the fly as part of the test case.
# XXX: Ideally, all the tests in this test program should be able to share
# the generated key, because creating it can be a very slow process on some
# machines.
#
# XXX2: copypasted from jmmv's sshd thingamob in the psshfs test.
# ideally code (and keys, like jmmv notes above) could be shared
#
start_sshd() {
	echo "Setting up SSH server configuration"
	sed -e "s,@SRCDIR@,$(atf_get_srcdir),g" -e "s,@WORKDIR@,$(pwd),g" \
	    $(atf_get_srcdir)/sshd_config.in >sshd_config || \
	    atf_fail "Failed to create sshd_config"
	atf_check -s ignore -o empty -e ignore \
	    cp $(atf_get_srcdir)/ssh_host_key .
	atf_check -s ignore -o empty -e ignore \
	    cp $(atf_get_srcdir)/ssh_host_key.pub .
	atf_check -s exit:0 -o empty -e empty chmod 400 ssh_host_key
	atf_check -s exit:0 -o empty -e empty chmod 444 ssh_host_key.pub

# Start in debugging mode so we don't have parent<->child privsep stuff
        env LD_PRELOAD=/usr/lib/librumphijack.so \
	    /usr/sbin/sshd -d -e -E "$(pwd)/out" -f ./sshd_config &
#	while [ ! -f sshd.pid ]; do
#		sleep 0.01
#	done
#	echo "SSH server started (pid $(cat sshd.pid))"
	sleep 1

	echo "Setting up SSH client configuration"
	atf_check -s exit:0 -o empty -e empty \
	    ssh-keygen -f ssh_user_key -t rsa -b 1024 -N "" -q
	atf_check -s exit:0 -o empty -e empty \
	    cp ssh_user_key.pub authorized_keys
	echo "127.0.0.1,localhost,::1 " \
	    "$(cat $(atf_get_srcdir)/ssh_host_key.pub)" >known_hosts || \
	    atf_fail "Failed to create known_hosts"
	atf_check -s exit:0 -o empty -e empty chmod 600 authorized_keys
	sed -e "s,@SRCDIR@,$(atf_get_srcdir),g" -e "s,@WORKDIR@,$(pwd),g" \
	    $(atf_get_srcdir)/ssh_config.in >ssh_config || \
	    atf_fail "Failed to create ssh_config"
	
	echo "sshd running"
}

atf_test_case ssh cleanup
ssh_head()
{
        atf_set "descr" "Test that hijacked ssh/sshd works"
}

ssh_body()
{
	atf_check -s exit:0 ${rumpnetsrv} ${RUMP_SERVER}
	# make sure clients die after we nuke the server
	export RUMPHIJACK_RETRYCONNECT='die'

	start_sshd

	# create some sort of directory for us to "ls"
	mkdir testdir
	cd testdir
	jot 11 | xargs touch
	jot 11 12 | xargs mkdir
	cd ..

	# From the PR (https://gnats.NetBSD.org/59278):
	#
	# > The LDAP problem has been fixed, but the new sshd-session
	# > wants to exec sshd-auth with stdin/out the network socket so the
	# > hijack code tries to dup(128, 0) and fails in:
	# >
	# >	if (fd_isrump(oldd)) {
	# >		int (*op_close)(int) = GETSYSCALL(host, CLOSE);
	# >
	# >		/* only allow fd 0-2 for cross-kernel dup */
	# >		if (!(newd >= 0 && newd <= 2 && !fd_isrump(newd))) {
	# >			errno = EBADF; <-----
	# >			return -1;
	# >		}
	# >
	# > The server client portion of the test works without rump...
	#
	atf_expect_fail "PR bin/59278: failing since openssh 10.0 update"

	# ignore stderr for now, prints environment in debug mode
	atf_check -s exit:0 -o save:ssh.out -e ignore			\
	    env LD_PRELOAD=/usr/lib/librumphijack.so			\
	    ssh -T -F ssh_config 127.0.0.1 env BLOCKSIZE=512		\
	    ls -li $(pwd)/testdir
	atf_check -s exit:0 -o file:ssh.out env BLOCKSIZE=512 		\
	    ls -li $(pwd)/testdir
}

ssh_cleanup()
{
	rump.halt
	# sshd dies due to RUMPHIJACK_RETRYCONNECT=1d6
}

test_nfs()
{

	magicstr='wind in my hair'
	# create ffs file system we'll be serving from
	atf_check -s exit:0 -o ignore newfs -F -s 10000 ffs.img

	# start nfs kernel server.  this is a mouthful
	export RUMP_SERVER=unix://serversock
	atf_check -s exit:0 rump_server $* ${RUMP_SERVER}

	atf_check -s exit:0 rump.ifconfig shmif0 create
	atf_check -s exit:0 rump.ifconfig shmif0 linkstr shmbus
	atf_check -s exit:0 rump.ifconfig shmif0 inet 10.1.1.1

	export RUMPHIJACK_RETRYCONNECT=die
	export LD_PRELOAD=/usr/lib/librumphijack.so

	atf_check -s exit:0 mkdir -p /rump/var/run
	atf_check -s exit:0 mkdir -p /rump/var/db
	atf_check -s exit:0 touch /rump/var/db/mountdtab
	atf_check -s exit:0 mkdir /rump/etc
	atf_check -s exit:0 mkdir /rump/export

	atf_check -s exit:0 -x \
	    'echo "/export -noresvport -noresvmnt 10.1.1.100" | \
		dd of=/rump/etc/exports 2> /dev/null'

	atf_check -s exit:0 rump.sysctl -q -w kern.module.autoload=1

	atf_check -s exit:0 -e ignore env RUMPHIJACK='path=/rump,blanket=/dk' \
		mount_ffs /dk /rump/export
	atf_check -s exit:0 -x "echo ${magicstr} > /rump/export/im_alive"

	# start rpcbind.  we want /var/run/rpcbind.sock
	export RUMPHIJACK='blanket=/var/run,socket=all' 
	atf_check -s exit:0 rpcbind

	# ok, then we want mountd in the similar fashion
	export RUMPHIJACK='blanket=/var/run:/var/db:/export,socket=all,path=/rump,vfs=all'
	atf_check -s exit:0 mountd /rump/etc/exports

	# finally, le nfschuck
	export RUMPHIJACK='blanket=/var/run,socket=all,vfs=all'
	atf_check -s exit:0 nfsd

	#
	# now, time for the client server and associated madness.
	#

	export RUMP_SERVER=unix://clientsock
	unset RUMPHIJACK
	unset LD_PRELOAD

	# at least the kernel server is easier
	atf_check -s exit:0 rump_server -lrumpvfs -lrumpnet		\
	    -lrumpnet_net -lrumpnet_netinet -lrumpnet_shmif -lrumpfs_nfs\
	    ${RUMP_SERVER}

	atf_check -s exit:0 rump.ifconfig shmif0 create
	atf_check -s exit:0 rump.ifconfig shmif0 linkstr shmbus
	atf_check -s exit:0 rump.ifconfig shmif0 inet 10.1.1.100

	export LD_PRELOAD=/usr/lib/librumphijack.so

	atf_check -s exit:0 mkdir /rump/mnt
	atf_check -s exit:0 mount_nfs 10.1.1.1:/export /rump/mnt

	atf_check -s exit:0 -o inline:"${magicstr}\n" cat /rump/mnt/im_alive
	atf_check -s exit:0 -o match:'.*im_alive$' ls -l /rump/mnt/im_alive
}


atf_test_case nfs cleanup
nfs_head()
{
        atf_set "descr" "Test hijacked nfsd and mount_nfs"

	# XXX Can probably make this work as nonroot, but need to
	# convince rpcbind running in the rump kernel server that it
	# has uid 0.
	atf_set "require.user" "root"
}

nfs_body()
{
	test_nfs -lrumpvfs -lrumpdev -lrumpnet -lrumpnet_net		\
	    -lrumpnet_netinet -lrumpnet_local -lrumpnet_shmif		\
	    -lrumpdev_disk -lrumpfs_ffs -lrumpfs_nfs -lrumpfs_nfsserver	\
	    -d key=/dk,hostpath=ffs.img,size=host
}

nfs_cleanup()
{
	RUMP_SERVER=unix://serversock rump.halt 2> /dev/null
	RUMP_SERVER=unix://clientsock rump.halt 2> /dev/null
	:
}

atf_test_case nfs_autoload cleanup
nfs_autoload_head()
{
        atf_set "descr" "Test hijacked nfsd with autoload from /stand"

	# XXX Can probably make this work as nonroot, but need to
	# convince rpcbind running in the rump kernel server that it
	# has uid 0.
	atf_set "require.user" "root"
}

nfs_autoload_body()
{
	[ `uname -m` = "i386" ] || atf_skip "test currently valid only on i386"
	atf_expect_fail "PR lib/54184"
	test_nfs -lrumpvfs -lrumpdev -lrumpnet -lrumpnet_net		\
	    -lrumpnet_netinet -lrumpnet_local -lrumpnet_shmif		\
	    -lrumpdev_disk -d key=/dk,hostpath=ffs.img,size=host
}

nfs_autoload_cleanup()
{
	nfs_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case http
	atf_add_test_case ssh
	atf_add_test_case nfs
	atf_add_test_case nfs_autoload
}
