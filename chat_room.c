#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_PORT        "5000"
#define MAX_CLIENTS         100
#define MAX_CLIENT_NAME_LEN 64
#define BUFFER_SIZE         1024
#define DAEMON_NAME         "Chat Room Server Daemon"

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
  char ip_address[INET6_ADDRSTRLEN];
  int  conn_fd;
  struct sockaddr *saddr;
} client_t;

// Shared resources
unsigned int *clients_count = NULL;
client_t     **clients      = NULL;
static int uid = 1;

// Turn server into daemon
void daemonize() {
  pid_t process_id;
  pid_t session_id;

  // Fork the process
  process_id = fork();
  if (process_id < 0){
    printf("Error occured during daemonizing. Exiting...\n");
    exit(EXIT_FAILURE);
  }

  // Exit from the parent process
  if (process_id > 0)
    exit(EXIT_SUCCESS);

  // Change file permissions mask
  umask(0);

  // Create a new session id for the child process
  session_id = setsid();
  if (session_id < 0)
    exit(EXIT_FAILURE);

  // Make "root" the working directory
  if ((chdir("/")) < 0)
    exit(EXIT_FAILURE);

  // Close all standard file descriptors
  close(0);
  close(1);
  close(2);
}

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

// Get IPv4 or IPv6 address of socket
void *get_address(struct sockaddr *sa){
  if (sa->sa_family == AF_INET)
    return &(((struct sockaddr_in*)sa)->sin_addr);
  else if (sa->sa_family == AF_INET6)
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
  else
    return NULL;
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

// Handle client communication
void* handle_client(client_t *client){
  char buffer_out[BUFFER_SIZE] = {0};
  char buffer_in[BUFFER_SIZE]  = {0};
  int  read_len = 0;

  *clients_count = *clients_count + 1;

  // Alert for joining of client
  printf("[INFO] Client connected    => ");
  printf("{ NAME => '%s', IP_ADDRESS => %s }\n", client->name, client->ip_address);
  sprintf(buffer_out, "[SERVER] User %s joined the room\n", client->name);
  send_message_all(buffer_out);

  // Receive input from client
  while((read_len = read(client->conn_fd, buffer_in, sizeof(buffer_in)-1)) > 0)
  {
    buffer_in[read_len] = '\0';
    buffer_out[0]   = '\0';
    // FIXME: Remove newline otherwise
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
        do {
          param = strtok(NULL, " ");
          strcat(buffer_out, param);
          strcat(buffer_out, " ");
        } while(param != NULL);
        send_message_others(buffer_out, client->name);
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
  }

  /* Close connection */
  shutdown(client->conn_fd, SHUT_RDWR);
  close(client->conn_fd);

  // Alert for leaving of client
  printf("[INFO] Client disconnected => ");
  printf("{ NAME => '%s', IP_ADDRESS => %s }\n", client->name, client->ip_address);
  sprintf(buffer_out, "[SERVER] User %s left the room\n", client->name);
  send_message_all(buffer_out);

  // Remove client from room and end process
  remove_client_from_room(client->name);
  free(client);
  *clients_count = *clients_count - 1;

  _exit(EXIT_SUCCESS);
}

// Main
int main(int argc, char *argv[]){
  int    listen_fd = 0;
  int    conn_fd   = 0;
  int    option    = 0;
  int    gai_err   = 0;
  int    yes       = 1;
  pid_t  child     = 0;
  char   address[INET6_ADDRSTRLEN] = {0};
  char  *port      = DEFAULT_PORT;
  bool   should_daemonize = false;
  size_t mem_size  = sizeof(clients_count) + sizeof(client_t)*MAX_CLIENTS;
  struct sockaddr_storage client_addr;
  struct addrinfo         hints;
  struct addrinfo        *server_info;
  struct addrinfo        *sip;

  // Process input arguments
  while ((option = getopt(argc, argv, "dp:")) != -1) {
    switch (option) {
    case 'd': should_daemonize = true; break;
    case 'p': port = optarg; break;
    case '?':
      if      (optopt == 'p')   { fprintf (stderr, "Option -%c requires an argument.\n", optopt) ;}
      else if (isprint(optopt)) { fprintf (stderr, "Unknown option `-%c'.\n", optopt);}
      else                      { fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);}
    default:
      fprintf(stderr, "Usage: %s [-d] [-p PORT]\n", argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  // Daemonize if necessary
  if (should_daemonize)
    daemonize();

  // Map shared memory
  clients_count = mmap((caddr_t)0, mem_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (clients_count == MAP_FAILED) {
    perror("[ERROR] mmap failed");
    exit(EXIT_FAILURE);
  }
  *clients_count = 0;
  clients = (client_t **)(clients_count+sizeof(clients_count));

  // Get all TCP/IP addresses
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if((gai_err = getaddrinfo(NULL, port, &hints, &server_info)) != 0) {
    fprintf(stderr, "[ERROR] getaddrinfo: %s\n", gai_strerror(gai_err));
    return 1;
  }

  // Assign address to socket;
  // bind to the first we can
  for(sip = server_info; sip != NULL; sip = sip->ai_next) {
    // Set-up socket
    listen_fd = socket(sip->ai_family, sip->ai_socktype, 0);
    if(listen_fd == -1) {
      perror("[ERROR] Socket creation failed");
      continue;
    }

    if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("[ERROR] Setting up socket failed");
      exit(EXIT_FAILURE);
    }

    // Bind to address
    if(bind(listen_fd, sip->ai_addr, sip->ai_addrlen) == -1){
      perror("[ERROR] Binding failed");
      continue;
    }

    // Allow incoming connections
    if(listen(listen_fd, 10) == -1){
      perror("[ERROR] Listening failed");
      exit(EXIT_FAILURE);
    }

    break;
  }

  freeaddrinfo(server_info);
  if (sip == NULL)  {
    fprintf(stderr, "[ERROR] Binding failed\n");
    exit(EXIT_FAILURE);
  }
  printf("[INFO] Server is started successfully on port %s\n", port);
  printf("[INFO] Protocol in use:  TCP/%s\n", (sip->ai_family == AF_INET ? "IPv4" : "IPv6"));

  // Accept clients
  while(1){
    socklen_t client_len = sizeof(client_addr);
    conn_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (conn_fd == -1) {
      perror("[ERROR] Accept failed");
      continue;
    }

    // Convert network address to string
    if(NULL == inet_ntop(client_addr.ss_family, 
                         get_address((struct sockaddr *)&client_addr),
                         address, sizeof(address)))
    {
      perror("[ERROR] Converting network address failed");
      continue;
    }

    // Check if max clients are connected
    if((*clients_count+1) == MAX_CLIENTS){
      {
        printf("[ERROR] Max clients reached\n");
        printf("[ERROR] Reject connection from %s\n", address);
      }
      close(conn_fd);
      continue;
    }

    // Configure client
    client_t *client = (client_t *)malloc(sizeof(client_t));
    client->saddr = (struct sockaddr *)&client_addr;
    client->conn_fd = conn_fd;
    sprintf(client->name, "%d", uid++);
    strcpy(client->ip_address, address);

    // Add client to the room and fork process
    add_client_to_room(client);

    if (!(child = fork())) {
      // Child process here
      close(listen_fd);
      handle_client(client);
    }
    printf("[INFO] Subprocess started with PID %d\n", child);
    close(conn_fd);
  }
}
