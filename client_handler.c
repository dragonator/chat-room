// System includes
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

// Custom includes
#include "client_handler.h"
#include "messages.h"

// Add client to room
client_t* register_client(char *name, char *address, int conn_fd){
  // Configure client
  client_t *client = get_free_slot();
  client->active = true;
  client->conn_fd = conn_fd;
  strcpy(client->name, name);
  strcpy(client->ip_address, address);

  return client;
}

// Remove client from room
void remove_client(char *name){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i].active && (strcmp(clients[i].name, name) == 0)){
        clients[i].active = false;
        return;
    }
  }
}

// List all active clients
void send_active_clients(int conn_fd){
  char message[BUFFER_SIZE];
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i].active){
      sprintf(message, "[USER] %s\n", clients[i].name);
      send_message_self(message, conn_fd);
    }
  }
}

// Get pointer to free slot from shrared memory
client_t* get_free_slot(){
  for(int i=0;i<MAX_CLIENTS;i++){
    if(!clients[i].active){
      return &clients[i];
    }
  }

  return NULL;
}

// Terminates string on newline character
void strip_newline(char *s){
  for(; *s != '\0' ; s++){
    if(*s == '\r' || *s == '\n'){
      *s = '\0';
      break;
    }
  }
}

// Handle client communication
void handle_client(client_t *client){
  char buffer_out[BUFFER_SIZE] = {0};
  char buffer_in[BUFFER_SIZE]  = {0};
  int  read_len = 0;

  *clients_count = *clients_count + 1;

  // Alert for joining of client
  printf("[INFO] Client connected    => ");
  printf("{ NAME => '%s', IP_ADDRESS => %s, FD => %d }\n",
         client->name, client->ip_address, client->conn_fd);
  sprintf(buffer_out, "[SERVER] User %s joined the room\n", client->name);
  send_message_others(buffer_out, client->conn_fd);

  // Receive input from client
  while((read_len = read(client->conn_fd, buffer_in, sizeof(buffer_in)-1)) > 0)
  {
    buffer_in[read_len-1] = '\0';
    buffer_out[0]   = '\0';
    strip_newline(buffer_in);

    // Ignore empty buffer
    if(!strlen(buffer_in)){
      continue;
    }

    // Handle command
    if(buffer_in[0] == CMD_PREFIX){
      char *command = NULL;
      char *param   = NULL;

      command = strtok(buffer_in, " ");
      if(strcmp(command, CMD_QUIT) == 0){
        break;
      }else if(strcmp(command, CMD_NAME) == 0){
        param = strtok(NULL, " ");
        if(param){
          char *old_name = strdup(client->name);
          strcpy(client->name, param);
          sprintf(buffer_out, "[INFO] Renamed %s to %s\n", old_name, client->name);
          free(old_name);
          send_message_all(buffer_out);
        }else{
          send_message_self("[ERROR] Username not provided\n", client->conn_fd);
        }
      }else if(strcmp(command, CMD_MSG) == 0){
        char *recipient = strtok(NULL, " ");
        if(recipient){
          param = strtok(NULL, " ");
          if(param){
            sprintf(buffer_out, "<%s>", client->name);
            while(param != NULL){
              strcat(buffer_out, " ");
              strcat(buffer_out, param);
              param = strtok(NULL, " ");
            }
            strcat(buffer_out, "\n");
            send_message_client(buffer_out, recipient);
          }else{
            send_message_self("[ERROR] Message not provided\n", client->conn_fd);
          }
        }else{
          send_message_self("[ERROR] Recipient not provided\n", client->conn_fd);
        }
      }else if(strcmp(command, CMD_MSG_ALL) == 0){
        param = strtok(NULL, " ");
        if(param){
          sprintf(buffer_out, "<%s>", client->name);
          while(param != NULL){
            strcat(buffer_out, " ");
            strcat(buffer_out, param);
            param = strtok(NULL, " ");
          }
        }else{
          send_message_self("[ERROR] Message not provided\n", client->conn_fd);
          continue;
        }
        send_message_others(buffer_out, client->conn_fd);
      }else if(strcmp(command, CMD_LIST) == 0){
        sprintf(buffer_out, "[INFO] Active clients: %d\n", *clients_count);
        send_message_self(buffer_out, client->conn_fd);
        send_active_clients(client->conn_fd);
      }else if(strcmp(command, CMD_HELP) == 0){
        strcat(buffer_out, CMD_QUIT"\tQuit chatroom\n");
        strcat(buffer_out, CMD_NAME"\t<name> Change nickname\n");
        strcat(buffer_out,  CMD_MSG"\t<user> <message> Send message to user\n");
        strcat(buffer_out, CMD_LIST"\tList active clients\n");
        strcat(buffer_out, CMD_HELP"\tShow help\n");
        send_message_self(buffer_out, client->conn_fd);
      }else{
        send_message_self("[ERROR] Command not recognized\n", client->conn_fd);
      }
    }else{
      send_message_self("[ERROR] Command not recognized\n", client->conn_fd);
    }

    buffer_in[0] = '\0';
    sleep(1);
  }

  // Alert for leaving of client
  printf("[INFO] Client disconnected => ");
  printf("{ NAME => '%s', IP_ADDRESS => %s }\n", client->name, client->ip_address);
  sprintf(buffer_out, "[SERVER] User %s left the room\n", client->name);
  send_message_all(buffer_out);

  // Remove client from room and end process
  remove_client(client->name);
  *clients_count = *clients_count - 1;
}
