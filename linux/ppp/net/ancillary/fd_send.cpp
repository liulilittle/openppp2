/***************************************************************************
 * libancillary - black magic on Unix domain sockets
 * (C) Nicolas George
 * fd_send.c - sending file descriptors
 ***************************************************************************/

 /*
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  *
  *  1. Redistributions of source code must retain the above copyright notice,
  *     this list of conditions and the following disclaimer.
  *  2. Redistributions in binary form must reproduce the above copyright
  *     notice, this list of conditions and the following disclaimer in the
  *     documentation and/or other materials provided with the distribution.
  *  3. The name of the author may not be used to endorse or promote products
  *     derived from this software without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
  * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
  * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  */

#ifndef _XPG4_2 /* Solaris sucks */
#define _XPG4_2
#endif

#include "ancillary.h"

int ancil_send_fds_with_buffer(int sock, const int* fds, unsigned n_fds, void* buffer) noexcept
{
    struct msghdr msghdr;
    char nothing = '!';
    struct iovec nothing_ptr;
    struct cmsghdr* cmsg;
    unsigned i;

    nothing_ptr.iov_base = &nothing;
    nothing_ptr.iov_len = 1;
    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_iov = &nothing_ptr;
    msghdr.msg_iovlen = 1;
    msghdr.msg_flags = 0;
    msghdr.msg_control = buffer;
    msghdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * n_fds;

    cmsg = CMSG_FIRSTHDR(&msghdr);
    cmsg->cmsg_len = msghdr.msg_controllen;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    for (i = 0; i < n_fds; i++)
    {
        ((int*)CMSG_DATA(cmsg))[i] = fds[i];
    }

    return (sendmsg(sock, &msghdr, 0) >= 0 ? 0 : -1);
}

#ifndef SPARE_SEND_FDS
int ancil_send_fds(int sock, const int* fds, unsigned n_fds) noexcept
{
    assert(n_fds <= ANCIL_MAX_N_FDS);

#ifdef ANCIL_FD_BUFFER_STRUCT
    ANCIL_FD_BUFFER(ANCIL_MAX_N_FDS) buffer;

    return (ancil_send_fds_with_buffer(sock, fds, n_fds, &buffer));
#else
    void* buffer = (void*)alloca(ppp::Malign<int>(sizeof(struct cmsghdr) + (sizeof(int) * ANCIL_MAX_N_FDS), 128));
    assert(buffer);

    return (ancil_send_fds_with_buffer(sock, fds, n_fds, buffer));
#endif
}
#endif /* SPARE_SEND_FDS */

#ifndef SPARE_SEND_FD
int ancil_send_fd(int sock, int fd) noexcept
{
#ifdef ANCIL_FD_BUFFER_STRUCT
    ANCIL_FD_BUFFER(1) buffer;

    return (ancil_send_fds_with_buffer(sock, &fd, 1, &buffer));
#else
    void* buffer = (void*)alloca(ppp::Malign<int>(sizeof(struct cmsghdr) + sizeof(int), 128));
    assert(buffer);

    return (ancil_send_fds_with_buffer(sock, &fd, 1, buffer));
#endif
}
#endif /* SPARE_SEND_FD */
