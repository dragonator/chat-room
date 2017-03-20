// System includes
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Custom includes
#include "ancillary.h"
#include "client_handler.h"
#include "file_descriptors.h"
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
void remove_client(int conn_fd){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i].active && clients[i].conn_fd == conn_fd){
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

// Get pending client
client_t* get_pending_client(){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(!clients[i].active && (strcmp(clients[i].ip_address, "") != 0)){
      return &clients[i];
    }
  }

  return NULL;
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
void handle_clients(){
  char buffer_out[BUFFER_SIZE] = {0};
  char buffer_in[BUFFER_SIZE]  = {0};
  int worker_fd;
  struct sockaddr_un server;
  int  read_len = 0;
  int  result;
  fd_set readset;

  worker_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (worker_fd < 0) {
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("[ERROR] socket failed");
      exit(EXIT_FAILURE);
  }
  server.sun_family = AF_UNIX;
  strcpy(server.sun_path, "server-worker-socket");

  // Ensue that server accepts connections before worker tries to connect
  usleep(10);
  if (connect(worker_fd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("[ERROR] connect() failed");
      close(worker_fd);
      exit(EXIT_FAILURE);
  }

  printf("[INFO] Worker connected to server:  FD => %d\n", worker_fd);

  // Receive input from client
  while(1)
  {
    // Construct set of fds
    FD_ZERO(&readset);
    FD_SET(worker_fd, &readset);
    for(int i=0 ; i<MAX_CLIENTS ; i++){
      if(clients[i].active){
        FD_SET(clients[i].conn_fd, &readset);
        //TODO get max fd number for select
      }
    }

    do {
      printf("[DEBUG] select: waits for input\n");
      result = select(MAX_CLIENTS+2, &readset, NULL, NULL, NULL);
    } while (result == -1 && errno == EINTR);

    if (result > 0) {
      if (FD_ISSET(worker_fd, &readset)) {
         printf("[DEBUG] Worker fd triggered\n");
        // The socket_fd has data available to be read
        client_t *client = get_pending_client();
        if(client == NULL){
          printf("[WARNING] No pending client\n");
        }
        else {
          ancil_recv_fd(worker_fd, &result);

          if(result < 0) {
            // This means the other side closed the socket
            close(worker_fd);
            exit(EXIT_SUCCESS);
          }
          else {
            *clients_count = *clients_count + 1;
            client->conn_fd = result;
            client->active = true;

            write(client->conn_fd, "<server> Welcome!\n", strlen("<server> Welcome!\n"));
            // Alert for joining of client
            printf("[INFO] Client connected    => ");
            printf("{ NAME => '%s', IP_ADDRESS => %s, FD => %d }\n",
                   client->name, client->ip_address, client->conn_fd);
            sprintf(buffer_out, "<SERVER> User %s joined the room\n", client->name);
            send_message_others(buffer_out, client->conn_fd);
          }
        }
        continue;
      }

      printf("[DEBUG] Client fd triggered\n");
      for(int i=0 ; i<MAX_CLIENTS ; i++){
        if (FD_ISSET(clients[i].conn_fd, &readset)){
          read_len = recv(clients[i].conn_fd, buffer_in, BUFFER_SIZE, 0);
          if (read_len == 0) {
            // This means the other side closed the socket
            close(clients[i].conn_fd);
            printf("[DEBUG] Removing client with fd '%d'\n", clients[i].conn_fd);
            continue;
          }

          //buffer_in[read_len] = '\0';
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
              // Close connection
              close(clients[i].conn_fd);

              // Alert for leaving of client
              printf("[INFO] Client disconnected => ");
              printf("{ NAME => '%s', IP_ADDRESS => %s }\n", clients[i].name, clients[i].ip_address);
              sprintf(buffer_out, "<SERVER> User %s left the room\n", clients[i].name);
              send_message_all(buffer_out);

              // Remove client from room and end process
              remove_client(clients[i].conn_fd);
              *clients_count = *clients_count - 1;

              break;
            }else if(strcmp(command, CMD_NAME) == 0){
              param = strtok(NULL, " ");
              if(param){
                char *old_name = strdup(clients[i].name);
                strcpy(clients[i].name, param);
                sprintf(buffer_out, "[INFO] Renamed %s to %s\n", old_name, clients[i].name);
                free(old_name);
                send_message_all(buffer_out);
              }else{
                send_message_self("[ERROR] Username not provided\n", clients[i].conn_fd);
              }
            }else if(strcmp(command, CMD_MSG) == 0){
              char *recipient = strtok(NULL, " ");
              if(recipient){
                param = strtok(NULL, " ");
                if(param){
                  sprintf(buffer_out, "<%s>", clients[i].name);
                  while(param != NULL){
                    strcat(buffer_out, " ");
                    strcat(buffer_out, param);
                    param = strtok(NULL, " ");
                  }
                  strcat(buffer_out, "\n");
                  send_message_client(buffer_out, recipient);
                }else{
                  send_message_self("[ERROR] Message not provided\n", clients[i].conn_fd);
                }
              }else{
                send_message_self("[ERROR] Recipient not provided\n", clients[i].conn_fd);
              }
            }else if(strcmp(command, CMD_MSG_ALL) == 0){
              param = strtok(NULL, " ");
              if(param){
                sprintf(buffer_out, "<%s>", clients[i].name);
                while(param != NULL){
                  strcat(buffer_out, " ");
                  strcat(buffer_out, param);
                  param = strtok(NULL, " ");
                }
                strcat(buffer_out, "\n");
              }else{
                send_message_self("[ERROR] Message not provided\n", clients[i].conn_fd);
                continue;
              }
              send_message_others(buffer_out, clients[i].conn_fd);
            }else if(strcmp(command, CMD_LIST) == 0){
              sprintf(buffer_out, "[INFO] Active clients: %d\n", *clients_count);
              send_message_self(buffer_out, clients[i].conn_fd);
              send_active_clients(clients[i].conn_fd);
            }else if(strcmp(command, CMD_HELP) == 0){
              strcat(buffer_out, CMD_QUIT"\tQuit chatroom\n");
              strcat(buffer_out, CMD_NAME"\t<name> Change nickname\n");
              strcat(buffer_out,  CMD_MSG"\t<user> <message> Send message to user\n");
              strcat(buffer_out, CMD_LIST"\tList active clients\n");
              strcat(buffer_out, CMD_HELP"\tShow help\n");
              send_message_self(buffer_out, clients[i].conn_fd);
            }else{
              send_message_self("[ERROR] Command not recognized\n", clients[i].conn_fd);
            }
          }else{
            send_message_self("[ERROR] Command not recognized\n", clients[i].conn_fd);
          }

          buffer_in[0] = '\0';
        }
      }
    }
    else if (result < 0) {
       // An error ocurred, just print it to stdout
       printf("[ERROR] select() failed: %s\n", strerror(errno));
       sleep(1);
    }
  }
}
