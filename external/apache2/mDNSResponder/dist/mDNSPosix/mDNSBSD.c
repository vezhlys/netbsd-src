/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mDNSUNP.h"
#include <ifaddrs.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <net/if_dl.h>


ssize_t
recvfrom_flags(int fd, void *ptr, size_t nbytes, int *flagsp,
    struct sockaddr *sa, socklen_t *salenptr, struct my_in_pktinfo *pktp,
    u_char *ttl)
{
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t n;

#ifdef CMSG_FIRSTHDR
    struct cmsghdr  *cmptr;
    union {
        struct cmsghdr cm;
        char control[1024];
    } control_un;

    *ttl = 255;         // If kernel fails to provide TTL data then assume the TTL was 255 as it should be

    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    msg.msg_flags = 0;
#else
    memset(&msg, 0, sizeof(msg));   /* make certain msg_accrightslen = 0 */
#endif /* CMSG_FIRSTHDR */

    msg.msg_name = (char *) sa;
    msg.msg_namelen = *salenptr;
    iov[0].iov_base = (char *)ptr;
    iov[0].iov_len = nbytes;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if ( (n = recvmsg(fd, &msg, *flagsp)) < 0)
        return(n);

    *salenptr = msg.msg_namelen;    /* pass back results */
    if (pktp) {
        /* 0.0.0.0, i/f = -1 */
        /* We set the interface to -1 so that the caller can
           tell whether we returned a meaningful value or
           just some default.  Previously this code just
           set the value to 0, but I'm concerned that 0
           might be a valid interface value.
         */
        memset(pktp, 0, sizeof(struct my_in_pktinfo));
        pktp->ipi_ifindex = -1;
    }
/* end recvfrom_flags1 */

/* include recvfrom_flags2 */
#ifndef CMSG_FIRSTHDR
    #warning CMSG_FIRSTHDR not defined. Will not be able to determine destination address, received interface, etc.
    *flagsp = 0;                    /* pass back results */
    return(n);
#else

    *flagsp = msg.msg_flags;        /* pass back results */
    if (msg.msg_controllen < (socklen_t)sizeof(struct cmsghdr) ||
        (msg.msg_flags & MSG_CTRUNC) || pktp == NULL)
        return(n);

    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr != NULL;
         cmptr = CMSG_NXTHDR(&msg, cmptr)) {

#ifdef  IP_PKTINFO
#if in_pktinfo_definition_is_missing
        struct in_pktinfo
        {
            int ipi_ifindex;
            struct in_addr ipi_spec_dst;
            struct in_addr ipi_addr;
        };
#endif
        if (cmptr->cmsg_level == IPPROTO_IP &&
            cmptr->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *tmp;
            struct sockaddr_in *sin = (struct sockaddr_in*)&pktp->ipi_addr;

            tmp = (struct in_pktinfo *) CMSG_DATA(cmptr);
            sin->sin_family = AF_INET;
            sin->sin_addr = tmp->ipi_addr;
            sin->sin_port = 0;
            pktp->ipi_ifindex = tmp->ipi_ifindex;
            continue;
        }
#endif

#ifdef  IP_RECVDSTADDR
        if (cmptr->cmsg_level == IPPROTO_IP &&
            cmptr->cmsg_type == IP_RECVDSTADDR) {
            struct sockaddr_in *sin = (struct sockaddr_in*)&pktp->ipi_addr;

            sin->sin_family = AF_INET;
            sin->sin_addr = *(struct in_addr*)CMSG_DATA(cmptr);
            sin->sin_port = 0;
            continue;
        }
#endif

#ifdef  IP_RECVIF
        if (cmptr->cmsg_level == IPPROTO_IP &&
            cmptr->cmsg_type == IP_RECVIF) {
            struct sockaddr_dl  *sdl = (struct sockaddr_dl *) CMSG_DATA(cmptr);
#ifndef HAVE_BROKEN_RECVIF_NAME
            int nameLen = (sdl->sdl_nlen < IFI_NAME - 1) ? sdl->sdl_nlen : (IFI_NAME - 1);
            strncpy(pktp->ipi_ifname, sdl->sdl_data, nameLen);
#endif
            pktp->ipi_ifindex = sdl->sdl_index;
#ifdef HAVE_BROKEN_RECVIF_NAME
            if (sdl->sdl_index == 0) {
                pktp->ipi_ifindex = *(uint_t*)sdl;
            }
#endif
            assert(pktp->ipi_ifname[IFI_NAME - 1] == 0);
            // null terminated because of memset above
            continue;
        }
#endif

#ifdef  IP_RECVTTL
        if (cmptr->cmsg_level == IPPROTO_IP &&
            cmptr->cmsg_type == IP_RECVTTL) {
            *ttl = *(u_char*)CMSG_DATA(cmptr);
            continue;
        }
        else if (cmptr->cmsg_level == IPPROTO_IP &&
                 cmptr->cmsg_type == IP_TTL) {  // some implementations seem to send IP_TTL instead of IP_RECVTTL
            *ttl = *(int*)CMSG_DATA(cmptr);
            continue;
        }
#endif

#if defined(IPV6_PKTINFO) && HAVE_IPV6
        if (cmptr->cmsg_level == IPPROTO_IPV6 &&
            cmptr->cmsg_type  == IPV6_2292_PKTINFO) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&pktp->ipi_addr;
            struct in6_pktinfo *ip6_info = (struct in6_pktinfo*)CMSG_DATA(cmptr);

            sin6->sin6_family   = AF_INET6;
#ifndef NOT_HAVE_SA_LEN
            sin6->sin6_len      = sizeof(*sin6);
#endif
            sin6->sin6_addr     = ip6_info->ipi6_addr;
            sin6->sin6_flowinfo = 0;
            sin6->sin6_scope_id = 0;
            sin6->sin6_port     = 0;
            pktp->ipi_ifindex   = ip6_info->ipi6_ifindex;
            continue;
        }
#endif

#if defined(IPV6_HOPLIMIT) && HAVE_IPV6
        if (cmptr->cmsg_level == IPPROTO_IPV6 &&
            cmptr->cmsg_type == IPV6_2292_HOPLIMIT) {
            *ttl = *(int*)CMSG_DATA(cmptr);
            continue;
        }
#endif
        assert(0);  // unknown ancillary data
    }
    return(n);
#endif /* CMSG_FIRSTHDR */
}
