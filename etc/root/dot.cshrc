#	$NetBSD: dot.cshrc,v 1.30 2025/01/11 06:43:28 tsutsui Exp $

alias	h	history
alias	j	jobs -l
alias	hup	'( set pid=$< ; kill -HUP $pid ) < /var/run/\!$.pid'
alias	la	ls -a
alias	lf	ls -FA
alias	ll	ls -l

alias	x	exit
alias	z	suspend

alias	back	'set back="$old"; set old="$cwd"; cd "$back"; unset back; dirs'
alias	cd	'set old="$cwd"; chdir \!*'
alias	pd	pushd
alias	pd2	pushd +2
alias	pd3	pushd +3
alias	pd4	pushd +4
alias	tset	'set noglob histchars=""; eval `\tset -s \!*`; unset noglob histchars'

setenv BLOCKSIZE 1k

# Uncomment the following line(s) to install binary packages
# from ftp.NetBSD.org via pkg_add.  (See also pkg_install.conf)
#setenv PKG_PATH "https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/`uname -p`/`uname -r|cut -f '1 2' -d.|cut -f 1 -d_`/All"

set history=1000
set path=(/sbin /usr/sbin /bin /usr/bin /usr/pkg/sbin /usr/pkg/bin /usr/X11R7/bin /usr/local/sbin /usr/local/bin)

# directory stuff: cdpath/cd/back
set cdpath=(/usr/src/{sys,bin,sbin,usr.{bin,sbin},lib,libexec,share,local,games})

if ($?prompt && -x /usr/bin/id ) then
	if (`/usr/bin/id -u` == 0) then
		set prompt="`hostname -s`# "
	else
		set prompt="`hostname -s`% "
	endif
endif

umask 022
