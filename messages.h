#ifndef __MESSAGES_H__
#define __MESSAGES_H__

// System includes
#include <string.h>

// Send message to all clients but the sender
void send_message_others(char *message, int conn_fd);

// Send message to all clients
void send_message_all(char *message);

// Send message to sender
void send_message_self(const char *message, int conn_fd);

// Send message to client by name
void send_message_client(char *message, char *name);

#endif
