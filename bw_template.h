//
// Created by yonmiroshnik on 11/14/24.
//

#include <string.h>

#ifndef WORKINGONIT_BW_TEMPLATE_H
#define WORKINGONIT_BW_TEMPLATE_H

#define N_CLIENTS 2  // Number of Client that connect to the server

// The following code is used to process a txt file input to the C program we made
#define MAX_LINE_LENGTH 1024

// All possible commands that can be used by a Client
#define GET_COMMAND "get"
#define SET_COMMAND "set"
#define SET_BY_SIZE_COMMAND "setsize"
#define PRINT_KV_COMMAND "printkv"
#define WARMUP_COMMAND "warmup"

// Used for helpful prints
#define CLIENT_PREFIX "Client: "
#define SERVER_PREFIX "Server: "
#define FIRST_WORD "The first word is: "
#define INVALID_INPUT "Invalid input format "

// Used to define control messages being sent
#define SET_MSG "SET"
#define GET_MSG "GET"
#define RDMA_SET_MSG "RDMA_SET"
#define RDMA_WRITE_MR_MSG "RDMA_WRITE_MR"
#define RDMA_READ_MR_MSG "RDMA_READ_MR"
#define SET_ACK_MSG "SET_ACK"
#define GET_ACK_MSG "GET_ACK"
#define RDMA_WRITE_ACK_MSG "RDMA_WRITE_ACK"
#define RDMA_READ_ACK_MSG "RDMA_READ_ACK"
#define PRINT_KV_MSG "PRINT_KV"
#define WARMUP_MSG "WARMUP"

// Max number of Key-Value pairs in the stores of the Server and Clients
//#define MAX_KEYS 100

// Max Size of Key is <4096 bytes
#define MAX_KEY_SIZE 4096

// Represents a Key-Value pair
struct kv_pair {
    char key[MAX_KEY_SIZE];           // Key of the Key-Value pair
    struct MR_place_pair* place_pair; // Contains the value and the Memory region that corresponds to it
};

// Allows to associate between a Memory Region and its corresponding malloced data mapping(value)
struct MR_place_pair {
    struct ibv_mr* mr; // Memory Region of the allocated memory
    char* value;       // Allocated memory of the value in the Key-Value pair
    int size;          // Size of the MR/Value
    int get_requests;  // Current number of RDMA GET requests that are reading from this pair
};

// Represents the whole Key-Value store data structure and
// provides the needed context to move the data between the Client and Server
struct kv_handle {
    struct pingpong_context *ctx; // RDMA context

    struct MR_place_pair default_send_buf; // Used by the kv_handle to send messages
    struct MR_place_pair default_recv_buf; // Used by the kv_handle to receive messages
};

#endif //WORKINGONIT_BW_TEMPLATE_H
