#ifndef __SHARED_H__
#define __SHARED_H__

// System includes
#include <arpa/inet.h>

// Custom includes
#include "client_handler.h"

// Define client type
typedef struct client_t {
  char name[MAX_CLIENT_NAME_LEN];
  char ip_address[INET6_ADDRSTRLEN];
  int  conn_fd;
  struct sockaddr *saddr;
} client_t;

// Shared resources
unsigned int *clients_count;
client_t     **clients;

#endif
