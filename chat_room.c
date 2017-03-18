// System includes
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

// Custom includes
#include "client_handler.h"
#include "shared.h"

// Macro definitions
#define DEFAULT_PORT        "5000"
#define DAEMON_NAME         "Chat Room Server Daemon"

static int uid = 1;

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
    perror("[ERROR] mmap failed");
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
    fprintf(stderr, "[ERROR] getaddrinfo: %s\n", gai_strerror(gai_err));
    exit(EXIT_FAILURE);
  }

  // Assign address to socket;
  // bind to the first we can
  for(sip = server_info; sip != NULL; sip = sip->ai_next) {
    // Set-up socket
    *listen_fd = socket(sip->ai_family, sip->ai_socktype, 0);
    if(*listen_fd == -1) {
      perror("[ERROR] Socket creation failed");
      continue;
    }

    if(setsockopt(*listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("[ERROR] Setting up socket failed");
      continue;
    }

    // Bind to address
    if(bind(*listen_fd, sip->ai_addr, sip->ai_addrlen) == -1){
      perror("[ERROR] Binding failed");
      continue;
    }

    // Allow incoming connections
    if(listen(*listen_fd, 10) == -1){
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
}

// Main
int main(int argc, char *argv[]){
  int    listen_fd   = 0;
  int    conn_fd     = 0;
  int    option      = 0;
  pid_t  child       = 0;
  char  *port        = DEFAULT_PORT;
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

    sprintf(username, "%d", uid++);
    client_t *client = register_client(username, address, conn_fd);

    if (!(child = fork())) {
      // Child process here
      close(listen_fd);
      handle_client(client);

      /* Close connection */
      shutdown(conn_fd, SHUT_RDWR);
      close(conn_fd);

      _exit(EXIT_SUCCESS);
    }
    printf("[INFO] Subprocess started with PID %d\n", child);
  }
}
