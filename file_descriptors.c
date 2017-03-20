// System includes
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Custom includes
#include "client_handler.h"
#include "shared.h"

// Send file-descriptor
int send_fd_to_worker(int worker_fd, int conn_fd, client_t client){
  struct msghdr hdr;
  struct iovec data;

  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  char dummy = '*';
  data.iov_base = &dummy;
  data.iov_len = sizeof(dummy);

  memset(&hdr, 0, sizeof(hdr));
  hdr.msg_name = NULL;
  hdr.msg_namelen = 0;
  hdr.msg_iov = &data;
  hdr.msg_iovlen = 1;
  hdr.msg_flags = 0;

  hdr.msg_control = cmsgbuf;
  hdr.msg_controllen = CMSG_LEN(sizeof(int));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&hdr);
  cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type  = SCM_RIGHTS;

  *(int*)CMSG_DATA(cmsg) = conn_fd;

  int n = sendmsg(worker_fd, &hdr, 0);

  if(n == -1)
    perror("[ERROR] sendmsg() failed");

  return n;
}

// Receive file-descriptor
int recv_fd_from_server(int worker_fd){
	int n;
	int fd;
	char buf[1];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cms[CMSG_SPACE(sizeof(int))];

	iov.iov_base = buf;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof msg);
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = (caddr_t)cms;
	msg.msg_controllen = sizeof cms;

	if((n=recvmsg(worker_fd, &msg, 0)) < 0)
		return -1;
	if(n == 0){
    perror("[ERROR] recvdmsg() failed: Unexpected EOF");
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	memmove(&fd, CMSG_DATA(cmsg), sizeof(int));
	return fd;
}
