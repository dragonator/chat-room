// System includes
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

// Custom includes
#include "ancillary.h"
#include "client_handler.h"
#include "file_descriptors.h"
#include "shared.h"

// Macro definitions
#define DEFAULT_PORT        "5000"
#define DAEMON_NAME         "Chat Room Server Daemon"

//static int uid = 1;

// Turn server into daemon
void daemonize(){
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

// Get IPv4 or IPv6 address of socket
void *get_address(struct sockaddr *sa){
  if (sa->sa_family == AF_INET)
    return &(((struct sockaddr_in*)sa)->sin_addr);
  else if (sa->sa_family == AF_INET6)
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
  else
    return NULL;
}

// Allocate shared memory
void* alloc_shared_memory(size_t size){
  void *result = mmap((caddr_t)0, size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (result == MAP_FAILED) {
    printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
    perror("[ERROR] mmap() failed");
    exit(EXIT_FAILURE);
  }

  return result;
}

// Assign address to socket
void bind_to_address(char *port, int *listen_fd){
  int    yes       = 1;
  int    gai_err   = 0;
  struct addrinfo  hints;
  struct addrinfo *server_info;
  struct addrinfo *sip;

  // Get all TCP/IP addresses
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if((gai_err = getaddrinfo(NULL, port, &hints, &server_info)) != 0) {
    printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
    printf("[ERROR] getaddrinfo() failed: %s\n", gai_strerror(gai_err));
    exit(EXIT_FAILURE);
  }

  // Assign address to socket;
  // bind to the first we can
  for(sip = server_info; sip != NULL; sip = sip->ai_next) {
    // Set-up socket
    *listen_fd = socket(sip->ai_family, sip->ai_socktype, 0);
    if(*listen_fd == -1) {
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("[ERROR] Socket creation failed");
      continue;
    }

    if(setsockopt(*listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("[ERROR] Setting up socket failed");
      continue;
    }

    // Bind to address
    if(bind(*listen_fd, sip->ai_addr, sip->ai_addrlen) == -1){
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("[ERROR] Binding failed");
      continue;
    }

    // Allow incoming connections
    if(listen(*listen_fd, 10) == -1){
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("[ERROR] Listening failed");
      exit(EXIT_FAILURE);
    }

    break;
  }

  freeaddrinfo(server_info);

  if (sip == NULL)  {
    printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
    printf("[ERROR] Binding failed\n");
    exit(EXIT_FAILURE);
  }
}

// Verify username
bool is_valid(char *username, int username_len){
  for(int i=0; (i<username_len-1) && (username[i] != '\0') ;i++){
    if(!isalpha(username[i]) && !isdigit(username[i]) && (username[i] != '_')){
      return false;
    }
  }

  return true;
}

bool is_name_available(char *username){
  for(int i=0 ; i<MAX_CLIENTS ; i++){
    if(clients[i].active && (strcmp(clients[i].name, username) == 0)){
        return false;
    }
  }

  return true;
}

// Main
int main(int argc, char *argv[]){
  int    listen_fd   = 0;
  int    conn_fd     = 0;
  int    worker_fd   = 0;
  int    worker_socket   = 0;
  int    option      = 0;
  pid_t  child       = 0;
  char  *port        = DEFAULT_PORT;
  //char  *username;
  ssize_t username_len = 0;
  bool   should_daemonize = false;
  char   address[INET6_ADDRSTRLEN]     = {0};
  char   username[MAX_CLIENT_NAME_LEN] = {0};
  size_t mem_size  = sizeof(clients_count) + sizeof(client_t)*MAX_CLIENTS;
  struct sockaddr_storage client_addr;

  // Process input arguments
  while ((option = getopt(argc, argv, "dp:")) != -1) {
    switch (option) {
    case 'd': should_daemonize = true; break;
    case 'p': port = optarg; break;
    case '?':
      if      (optopt == 'p')   fprintf(stderr, "Option -%c requires an argument.\n", optopt);
      else if (isprint(optopt)) fprintf(stderr, "Unknown option `-%c'.\n", optopt);
      else                      fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
    default:
      fprintf(stderr, "Usage: %s [-d] [-p PORT]\n", argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  // Daemonize if necessary
  if (should_daemonize)
    daemonize();

  // Map shared memory
  clients_count = alloc_shared_memory(mem_size);
  *clients_count = 0;
  clients = (client_t *)(clients_count+sizeof(clients_count));

  // Assign address to socket
  bind_to_address(port, &listen_fd);
  printf("[INFO] Server is started successfully on port %s\n", port);

  // Create UNIX domain socket
  worker_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, "server-worker-socket", sizeof(addr.sun_path)-1);

  // Bind to address
  unlink("server-worker-socket");
  if(bind(worker_socket, (struct sockaddr*)&addr, sizeof(addr)) == -1){
    printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
    perror("[ERROR] bind() failed");
    exit(EXIT_FAILURE);
  }

  // Allow incoming connections
  if(listen(worker_socket, 1) == -1){
    printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
    perror("[ERROR] Listening failed");
    exit(EXIT_FAILURE);
  }

  // Start worker
  if (!(child = fork())) {
    // Worker process here
    close(worker_socket);
    handle_clients();

    exit(EXIT_FAILURE);
  }
  printf("[INFO] Worker process started with PID %d\n", child);

  // Accept connection from worker
  worker_fd = accept(worker_socket, 0, 0);
  if (worker_fd == -1){
    printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
    perror("[ERROR] accept() failed");
  }

  // Accept clients
  while(1){
    socklen_t client_len = sizeof(client_addr);
    conn_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (conn_fd == -1) {
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("[ERROR] accept() failed");
      continue;
    }

    // Convert network address to string
    if(NULL == inet_ntop(client_addr.ss_family,
                         get_address((struct sockaddr *)&client_addr),
                         address, sizeof(address)))
    {
      printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
      perror("Converting network address failed");
      continue;
    }

    // Check if max clients are connected
    if((*clients_count+1) == MAX_CLIENTS){
      {
        printf("[ERROR in %s near line %d]\n", __FILE__, __LINE__);
        printf("[ERROR] Max clients reached\n");
        printf("[ERROR] Reject connection from %s\n", address);
      }
      close(conn_fd);
      continue;
    }

    client_t *client = get_free_slot();
    // Pick username
    while(1) {
      write(conn_fd, "<SERVER> Pick username: \n", 25);
      if((username_len = recv(conn_fd, username, MAX_CLIENT_NAME_LEN, 0)) == 0){
          username[0] = '\0';
          break;
      }
      
      strip_newline(username);
      
      if(!is_valid(username, username_len)){
        write(conn_fd, "<SERVER> Invalid username.Try again.\n", 37);
        continue;
      }

      if(!is_name_available(username)){
        write(conn_fd, "<SERVER> Username is taken.Try again.\n", 37);
        continue;
      }

      break;
    };
    
    if(!username_len)
      continue;

    //sprintf(client->name, "%d", uid++);
    strcpy(client->name, username);
    strcpy(client->ip_address, address);
    printf("[INFO] Sending fd to worker: %d\n", conn_fd);
    ancil_send_fd(worker_fd, conn_fd);
  }

  close(worker_fd);
  close(listen_fd);
}
