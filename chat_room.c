#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT                5002
#define MAX_CLIENTS         100
#define MAX_CLIENT_NAME_LEN 64
#define BUFFER_SIZE         1024

// Commands
#define CMD_PREFIX  '.'
#define CMD_HELP    ".help"
#define CMD_QUIT    ".quit"
#define CMD_NAME    ".name"
#define CMD_MSG     ".msg"
#define CMD_MSG_ALL ".msg_all"
#define CMD_LIST    ".list"

// Define client type
typedef struct client_t {
  char name[MAX_CLIENT_NAME_LEN];
  int  conn_fd;
  struct sockaddr_in addr;
} client_t;

static unsigned int clients_count = 0;
client_t *clients[MAX_CLIENTS];
static int uid = 1;

// Add client to room
void add_client_to_room(client_t *cl){
  for(int i=0;i<MAX_CLIENTS;i++){
    if(!clients[i]){
      clients[i] = cl;
      return;
    }
  }
}

// Remove client from room
void remove_client_from_room(char *name){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i] && (strcmp(clients[i]->name, name) == 0)){
        clients[i] = NULL;
        return;
    }
  }
}

// Send message to all clients but the sender
void send_message_others(char *message, char *name){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i] && (strcmp(clients[i]->name, name) != 0)){
        write(clients[i]->conn_fd, message, strlen(message));
    }
  }
}

// Send message to all clients
void send_message_all(char *message){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i]){
      write(clients[i]->conn_fd, message, strlen(message));
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
    if(clients[i] && (strcmp(clients[i]->name, name) == 0)){
        write(clients[i]->conn_fd, message, strlen(message));
        return;
    }
  }
}

// List all active clients
void send_active_clients(int conn_fd){
  char message[BUFFER_SIZE];
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i]){
      sprintf(message, "[USER] %s\n", clients[i]->name);
      send_message_self(message, conn_fd);
    }
  }
}

//=================
/* Strip CRLF */
void strip_newline(char *s){
  while(*s != '\0'){
    if(*s == '\r' || *s == '\n'){
      *s = '\0';
    }
    s++;
  }
}
//=================

/* Handle all communication with the client */
void* handle_client(void *args){
  char buffer_out[BUFFER_SIZE] = {0};
  char buffer_in[BUFFER_SIZE]  = {0};
  char address[INET6_ADDRSTRLEN] = {0};
  int  read_len = 0;
  client_t *client = (client_t *)args;

  clients_count++;

  // Alert for joining of client
  if(NULL != inet_ntop(AF_INET, &client->addr,
                       address, sizeof(address)))
  {
    printf("[INFO] Client connected:\n");
    printf("[INFO] NAME : %s\n", client->name);
    printf("[INFO] IP   : %s\n", address);
  }
  else {
    perror("[ERROR] inet_ntop failed");
    // TODO
  }

  sprintf(buffer_out, "[SERVER] User %s joined the room\n", client->name);
  send_message_all(buffer_out);

  /* Receive input from client */
  while((read_len = read(client->conn_fd, buffer_in, sizeof(buffer_in)-1)) > 0)
  {
    buffer_in[read_len] = '\0';
    buffer_out[0]   = '\0';
    // FIXME: Remove newline otherwise
    strip_newline(buffer_in);

    /* Ignore empty buffer */
    if(!strlen(buffer_in)){
      continue;
    }
  
    /* Special options */
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
        do {
          param = strtok(NULL, " ");
          strcat(buffer_out, param);
          strcat(buffer_out, " ");
        } while(param != NULL);
        send_message_others(buffer_out, client->name);
      }else if(strcmp(command, CMD_LIST) == 0){
        sprintf(buffer_out, "[INFO] Active clients: %d\n", clients_count);
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
  }

  /* Close connection */
  close(client->conn_fd);
  sprintf(buffer_out, "[SERVER] User %s left the room\n", client->name);
  send_message_all(buffer_out);

  // Remove client from room and end process
  remove_client_from_room(client->name);
  free(client);
  clients_count--;

  // Alert for leaving of client
  if(NULL != inet_ntop(AF_INET, &client->addr,
                       address, sizeof(address)))
  {
    printf("[INFO] Client disconnected:\n");
    printf("[INFO] NAME : %s\n", client->name);
    printf("[INFO] IP   : %s\n", address);
  }

  else {
    perror("[ERROR] inet_ntop failed\n");
    // TODO
  }
  pthread_detach(pthread_self());
  
  return NULL;
}

int main(){
  int  listen_fd = 0;
  int  conn_fd   = 0;
  char address[INET6_ADDRSTRLEN] = {0};
  struct sockaddr_in serv_addr;
  struct sockaddr_in client_addr;
  pthread_t thread_id;

  // Set-up socket
  listen_fd                 = socket(AF_INET, SOCK_STREAM, 0);
  serv_addr.sin_family      = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port        = htons(PORT); 

  // Assign addres to socket
  if(bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
    perror("[ERROR] Binding failed");
    return 1;
  }

  // Allow incoming connections
  if(listen(listen_fd, 10) < 0){
    perror("[ERROR] Listening failed");
    return 1;
  }

  printf("[INFO] Server started successfully.\n");

  // Accept clients
  while(1){
    socklen_t client_len = sizeof(client_addr);
    conn_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);

    // Check if max clients are connected
    if((clients_count+1) == MAX_CLIENTS){
      if(NULL != inet_ntop(AF_INET, &client_addr,
                           address, sizeof(address)))
      {
        printf("[ERROR] Max clients reached\n");
        printf("[ERROR] Reject connection from %s\n", address);
      }
      close(conn_fd);
      continue;
    }

    // Configure client
    client_t *client = (client_t *)malloc(sizeof(client_t));
    client->addr = client_addr;
    client->conn_fd = conn_fd;
    sprintf(client->name, "%d", uid++);

    // Add client to the room and fork process
    add_client_to_room(client);
    // TODO: Fork process instead of thread
    pthread_create(&thread_id, NULL, &handle_client, (void*)client);
  }
}
