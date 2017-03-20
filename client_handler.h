#ifndef __CLIENT_HANDLER_H__
#define __CLIENT_HANDLER_H__

// Macro definitions
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
client_t* register_client(char *name, char *ip_address, int conn_fd);

// Remove client from room
void remove_client(int conn_fd);

// List all active clients
void send_active_clients(int conn_fd);

// Handle client communication
void handle_clients();

// Get pending client
client_t* get_pending_client();

// Get pointer to free slot from shrared memory
client_t* get_free_slot();

// Terminates string on newline character
void strip_newline(char *s);
#endif
