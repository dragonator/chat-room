#ifndef __SHARED_H__
#define __SHARED_H__

// System includes
#include <arpa/inet.h>
#include <stdbool.h>

// Custom includes
#include "client_handler.h"

// Macro definitions
#define MAX_CLIENTS         100
#define MAX_CLIENT_NAME_LEN 64

// Define client type
typedef struct client_t {
  char  name[MAX_CLIENT_NAME_LEN];
  char  ip_address[INET6_ADDRSTRLEN];
  int   conn_fd;
  bool  active;
} client_t;

// Shared resources
unsigned int *clients_count;
client_t     *clients;

#endif
