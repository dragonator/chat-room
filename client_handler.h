#ifndef __CLIENT_HANDLER_H__
#define __CLIENT_HANDLER_H__

// Macro definitions
#define MAX_CLIENTS         100
#define MAX_CLIENT_NAME_LEN 64
#define BUFFER_SIZE         1024

// Custom includes
#include "shared.h"

// Commands
#define CMD_PREFIX  '.'
#define CMD_HELP    ".help"
#define CMD_QUIT    ".quit"
#define CMD_NAME    ".name"
#define CMD_MSG     ".msg"
#define CMD_MSG_ALL ".msg_all"
#define CMD_LIST    ".list"

// Add client to room
void add_client_to_room(client_t *cl);

// Remove client from room
void remove_client_from_room(char *name);

// List all active clients
void send_active_clients(int conn_fd);

// Handle client communication
void* handle_client(client_t *client);

#endif
