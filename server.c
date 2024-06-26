//
// Created by amittai.lerer on 6/5/24.


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8081
#define BUFFER_SIZE 1048576 // 1MB
#define MAX_CONECTION_IN_BACKLOG 3
#define SOCKET_FAILED_MSG "socket failed"
#define SET_SOCK_OPT_PERROE_MSG "setsockopt"
#define BIND_ERROR_MSG "bind failed"
#define LISTEN_PERROR_MSG "listen"
#define NEW_SOCKET_PERROR_MSG "accept"
#define READ_PERROR_MSG "read"
#define CONNECT_CLIENT_MSG "Connected to client\n"
#define DISCONNECT_CLIENT_MSG "Client disconnected\n"


int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char *buffer = malloc(BUFFER_SIZE);

    // Create a socket file descriptor
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror(SOCKET_FAILED_MSG);
        exit(EXIT_FAILURE);
    }

    // Set socket options to allow reuse of address and port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror(SET_SOCK_OPT_PERROE_MSG);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Address structure setup
    memset(&address, 0, sizeof(address)); // Initialize address structure to zero
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Accept connections from any IP address
    address.sin_port = htons(PORT); // Convert port number to network byte order

    // Bind the socket to the specified address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror(BIND_ERROR_MSG);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections. Maximum 3 connections allowed in the backlog.
    if (listen(server_fd, MAX_CONECTION_IN_BACKLOG) < 0) {
        perror(LISTEN_PERROR_MSG);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Accept incoming connection
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror(NEW_SOCKET_PERROR_MSG);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf(CONNECT_CLIENT_MSG);

    // Read data from client until the connection is closed
    ssize_t bytes_read;
    while ((bytes_read = read(new_socket, buffer, BUFFER_SIZE)) > 0) {}
    if (bytes_read < 0) {
        perror(READ_PERROR_MSG);
        close(new_socket);
        close(server_fd);
        free(buffer);
        exit(EXIT_FAILURE);
    } else if (bytes_read == 0) {
        printf(DISCONNECT_CLIENT_MSG);
    }

    // Clean up: Close sockets and free allocated memory
    close(new_socket);
    close(server_fd);
    free(buffer);
    return 0;
}
