// System includes
#include <unistd.h>

// Custom includes
#include "client_handler.h"
#include "messages.h"

// Send message to all clients but the sender
void send_message_others(char *message, int conn_fd){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i].active && (clients[i].conn_fd != conn_fd)){
      write(clients[i].conn_fd, message, strlen(message));
    }
  }
}

// Send message to all clients
void send_message_all(char *message){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i].active){
      write(clients[i].conn_fd, message, strlen(message));
    }
  }
}

// Send message to sender
void send_message_self(const char *message, int conn_fd){
  write(conn_fd, message, strlen(message));
}

// Send message to client by name
void send_message_client(char *message, char *name){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i].active && (strcmp(clients[i].name, name) == 0)){
        write(clients[i].conn_fd, message, strlen(message));
        return;
    }
  }
}

