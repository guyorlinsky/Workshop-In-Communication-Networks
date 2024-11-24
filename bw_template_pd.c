/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// TODO do we use C89 strcpy_s with error checking?
// TODO use safe_malloc? https://stackoverflow.com/questions/35026910/malloc-error-checking-methods


#define _GNU_SOURCE

#include "bw_template.h"

// We got the linked list implementation here: https://github.com/skorks/c-linked-list with slight modifications
// to make it have a key and data associated with each node
#include "linkedlist_pairs.h"


//#include <libcaf.h>
//#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
//#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
//#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
//#include <time.h>
//#include <sys/param.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <infiniband/verbs.h>
#include <byteswap.h>

#define WC_BATCH (1)

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return bswap_64(x);
}
static inline uint64_t ntohll(uint64_t x)
{
    return bswap_64(x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return x;
}
static inline uint64_t ntohll(uint64_t x)
{
    return x;
}
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

static bool PRINT_MSGS = true;

enum {
    PINGPONG_RECV_WRID = 1,
    PINGPONG_SEND_WRID = 2,
    PINGPONG_RDMA_OP = 3,
};

static int page_size;

struct pingpong_context {
    struct ibv_context *context; // IBV context for the RDMA device
    struct ibv_comp_channel *channel; // Completion Channel for event notifications
    struct ibv_pd *pd;         // Protection Domain for managing access rights
    struct ibv_mr *mr;         // Memory Region for registering the buffer
    struct ibv_cq *cq;         // Completion Queue for managing completion notifications
    struct ibv_qp *qp;         // Queue Pair for managing message exchange
    void *buf;                  // Pointer to the buffer for message data
    int size;                   // Size of the buffer for message data
    int rx_depth;               // Depth of the receive queue
    int routs;                  // Number of outstanding receive requests
    struct ibv_port_attr	portinfo;
};

struct pingpong_dest {
    uint16_t lid;   // Local Identifier for the port (used for routing)
    uint32_t qpn;   // Queue Pair Number for the connection
    uint32_t psn;   // Packet Sequence Number used for ordering messages
    union ibv_gid gid; // Global Identifier for the RDMA connection
};

enum ibv_mtu pp_mtu_to_enum(int mtu)
{
    switch (mtu) {
        case 256:  return IBV_MTU_256;
        case 512:  return IBV_MTU_512;
        case 1024: return IBV_MTU_1024;
        case 2048: return IBV_MTU_2048;
        case 4096: return IBV_MTU_4096;
        default:   return -1;
    }
}

static struct ibv_pd* comp_pd;
static struct ibv_context* comp_context;


/**
 * pp_get_local_lid - Retrieve the Local Identifier (LID) of the specified port.
 * @context: A pointer to the ibv_context representing the device.
 * @port: The port number from which the LID will be retrieved.
 *
 * This function queries the attributes of a specified port using ibv_query_port
 * and returns the Local Identifier (LID) of the port. The LID is a unique
 * identifier in InfiniBand networks used for addressing within the local subnet.
 *
 * Return:
 *   - 0 if the query to the port fails (error case).
 *   - The LID of the port on success.
 */
uint16_t pp_get_local_lid(struct ibv_context *context, int port)
{
    struct ibv_port_attr attr;  // Data structure to hold port attributes.

    // Query the port attributes and return 0 if it fails.
    if (ibv_query_port(context, port, &attr))
        return 0;

    // Return the Local Identifier (LID) from the queried attributes.
    return attr.lid;
}

int pp_get_port_info(struct ibv_context *context, int port,
                     struct ibv_port_attr *attr)
{
    return ibv_query_port(context, port, attr);
}

/**
 * wire_gid_to_gid - Convert a wire-format GID string into an ibv_gid structure.
 * @wgid: The input string containing the GID in a wire format (hexadecimal representation).
 * @gid: A pointer to an ibv_gid union where the converted GID will be stored.
 *
 * This function parses a wire-format GID string, which represents a Global Identifier (GID)
 * in hexadecimal form, and converts it into a format suitable for the `ibv_gid` structure.
 * The function breaks the wire-format string into 4 chunks, converts each to a 32-bit
 * integer, then stores the result in the raw byte array of the GID in network byte order.
 *
 * Details:
 * - The GID string is expected to be 32 hexadecimal characters long.
 * - The function processes the string in 8-character blocks (4 bytes at a time).
 * - Each block is converted from a hexadecimal string to a 32-bit integer, then stored
 *   in the `gid->raw` field after converting it to network byte order using `ntohl`.
 */
void wire_gid_to_gid(const char *wgid, union ibv_gid *gid)
{
    char tmp[9];          // Temporary buffer to hold 8-character chunks (plus null terminator).
    uint32_t v32;         // 32-bit value to store the converted integer from hex.
    int i;

    // Loop through the wire-format GID string in 8-character chunks (32 bits at a time).
    for (tmp[8] = 0, i = 0; i < 4; ++i) {
        // Copy 8 characters from the wire-format GID string into the temporary buffer.
        memcpy(tmp, wgid + i * 8, 8);

        // Convert the 8-character chunk from hexadecimal to a 32-bit integer.
        sscanf(tmp, "%x", &v32);

        // Store the 32-bit integer into the raw GID field, converting to network byte order.
        *(uint32_t *)(&gid->raw[i * 4]) = ntohl(v32);
    }
}

/**
 * gid_to_wire_gid - Convert an ibv_gid structure into a wire-format GID string.
 * @gid: A pointer to an ibv_gid union containing the GID to be converted.
 * @wgid: A char array where the converted wire-format GID string will be stored.
 *
 * This function converts an ibv_gid structure into a wire-format GID string
 * (a 32-character hexadecimal string). It processes the raw GID data in 32-bit chunks,
 * converts each to network byte order, and then formats the result as an 8-character
 * hexadecimal string (one chunk at a time).
 *
 * Details:
 * - The function processes the GID data in 4 chunks of 32 bits (4 bytes) each.
 * - Each 32-bit chunk is converted to network byte order using `htonl` and then
 *   formatted into an 8-character hexadecimal string using `sprintf`.
 * - The resulting hexadecimal string is stored in `wgid` (the output buffer).
 */
void gid_to_wire_gid(const union ibv_gid *gid, char wgid[])
{
    int i;

    // Loop through the GID's raw data in 4-byte (32-bit) chunks.
    for (i = 0; i < 4; ++i)
        // Convert each 32-bit chunk to network byte order and format it as an 8-character hex string.
        sprintf(&wgid[i * 8], "%08x", htonl(*(uint32_t *)(gid->raw + i * 4)));
}


/**
 * pp_connect_ctx - Transition the QP (Queue Pair) through the states needed for communication.
 * @ctx: A pointer to the pingpong_context structure, which contains the RDMA context, QP, etc.
 * @port: The port number on which the connection is established.
 * @my_psn: The packet sequence number (PSN) for this side of the connection.
 * @mtu: The maximum transmission unit (MTU) for the connection.
 * @sl: The service level, which defines the virtual lane for traffic.
 * @dest: A pointer to the pingpong_dest structure, which contains the destination LID, QPN, PSN, and GID.
 * @sgid_idx: The index of the source GID to use if the destination is on a different subnet.
 *
 * This function configures and transitions the queue pair (QP) from the RESET state to the Ready-to-Receive (RTR)
 * state, then to the Ready-to-Send (RTS) state, enabling communication between the local and remote RDMA endpoints.
 *
 * Steps:
 * 1. Initializes a `struct ibv_qp_attr` with attributes for the RTR state.
 * 2. Modifies the QP to the RTR state using `ibv_modify_qp`.
 * 3. If the destination uses a global GID (for RoCE or IPv6), additional settings for the Global Routing Header (GRH)
 *    are configured.
 * 4. After transitioning to RTR, the QP is modified to the RTS state, setting the timeout, retry counts, and sequence number.
 *
 * Return:
 *   - 0 on success.
 *   - 1 on failure (failure to modify the QP state to RTR or RTS).
 */
static int pp_connect_ctx(struct pingpong_context *ctx, int port, int my_psn,
                          enum ibv_mtu mtu, int sl,
                          struct pingpong_dest *dest, int sgid_idx)
{
    // Step 1: Set the QP attributes for the RTR (Ready to Receive) state.
    struct ibv_qp_attr attr = {
            .qp_state           = IBV_QPS_RTR,       // Transition QP to RTR state.
            .path_mtu           = mtu,               // Set the MTU size for the connection.
            .dest_qp_num        = dest->qpn,         // Destination QP number.
            .rq_psn             = dest->psn,         // Initial receive packet sequence number.
            .max_dest_rd_atomic = 1,                 // Max outstanding RDMA read/atomic operations.
            .min_rnr_timer      = 12,                // Minimum receive not ready (RNR) timer.
            .ah_attr            = {                  // Address handle attributes for path routing.
                    .is_global      = 0,                 // Is this a global route? (0 for local LID-based routing)
                    .dlid           = dest->lid,         // Destination LID (Local Identifier).
                    .sl             = sl,                // Service level (QoS, virtual lane).
                    .src_path_bits  = 0,                 // Source path bits (for path selection in the switch).
                    .port_num       = port               // The local port number to use for this connection.
            }
    };

    // Step 2: If the destination has a global GID (RoCE or IPv6), configure the Global Routing Header (GRH).
    if (dest->gid.global.interface_id) {
        attr.ah_attr.is_global = 1;              // Enable global routing.
        attr.ah_attr.grh.hop_limit = 1;          // Set the GRH hop limit (similar to TTL in IP networks).
        attr.ah_attr.grh.dgid = dest->gid;       // Set the destination GID.
        attr.ah_attr.grh.sgid_index = sgid_idx;  // Set the source GID index for the connection.
    }

    // Step 3: Modify the QP to transition it to the RTR state.
    if (ibv_modify_qp(ctx->qp, &attr,
                      IBV_QP_STATE              |    // Transition to RTR state.
                      IBV_QP_AV                 |    // Set the address vector (AV).
                      IBV_QP_PATH_MTU           |    // Set the MTU size.
                      IBV_QP_DEST_QPN           |    // Set the destination QP number.
                      IBV_QP_RQ_PSN             |    // Set the receive PSN.
                      IBV_QP_MAX_DEST_RD_ATOMIC |    // Set the max RDMA read/atomic operations.
                      IBV_QP_MIN_RNR_TIMER)) {       // Set the RNR timeout.
        fprintf(stderr, "Failed to modify QP to RTR\n");
        return 1;
    }

    // Jonathan notice: what is the point of making it RTR and then RTS? why not just instantly RTS?
    // Step 4: Modify the QP attributes for the RTS (Ready to Send) state.
    attr.qp_state       = IBV_QPS_RTS;      // Transition QP to RTS state.
    attr.timeout        = 14;               // Set the timeout for retries.
    attr.retry_cnt      = 7;                // Set the number of retries on send timeout.
    attr.rnr_retry      = 7;                // Set the number of retries for receiver not ready (RNR).
    attr.sq_psn         = my_psn;           // Set the send packet sequence number.
    attr.max_rd_atomic  = 1;                // Max outstanding RDMA read/atomic operations.

    // Step 5: Modify the QP to transition it to the RTS state.
    if (ibv_modify_qp(ctx->qp, &attr,
                      IBV_QP_STATE              |    // Transition to RTS state.
                      IBV_QP_TIMEOUT            |    // Set the timeout value.
                      IBV_QP_RETRY_CNT          |    // Set the retry count.
                      IBV_QP_RNR_RETRY          |    // Set the RNR retry count.
                      IBV_QP_SQ_PSN             |    // Set the send PSN.
                      IBV_QP_MAX_QP_RD_ATOMIC)) {    // Set the max outstanding RDMA read/atomic operations.
        fprintf(stderr, "Failed to modify QP to RTS\n");
        return 1;
    }

    // Success: the QP has been modified to both RTR and RTS states.
    return 0;
}

/**
 * pp_client_exch_dest - Establishes a connection to the server and exchanges RDMA destination info.
 * @servername: The name or IP address of the server to connect to.
 * @port: The port number on which to establish the connection.
 * @my_dest: A pointer to the pingpong_dest structure containing the local RDMA address info.
 *
 * This function initiates a TCP connection to a server and exchanges RDMA connection information,
 * such as LID (Local Identifier), QPN (Queue Pair Number), PSN (Packet Sequence Number), and GID (Global Identifier).
 *
 * Steps:
 * 1. Resolves the server's address using `getaddrinfo`.
 * 2. Connects to the server via a TCP socket.
 * 3. Sends the client's RDMA destination information to the server.
 * 4. Receives the server's RDMA destination information.
 * 5. Converts the wire-format GID back into a usable `ibv_gid` format.
 *
 * Return:
 *   - A pointer to a `pingpong_dest` structure containing the remote destination information on success.
 *   - NULL on failure (e.g., if the connection fails, if memory allocation fails, or if the exchange of information fails).
 */
static struct pingpong_dest *pp_client_exch_dest(const char *servername, int port,
                                                 const struct pingpong_dest *my_dest)
{
    struct addrinfo *res, *t;
    struct addrinfo hints = {
            .ai_family   = AF_INET,      // Use IPv4 addresses.
            .ai_socktype = SOCK_STREAM   // Use TCP sockets.
    };
    char *service;
    char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int n;
    int sockfd = -1;
    struct pingpong_dest *rem_dest = NULL;
    char gid[33];                    // Buffer to hold the wire-format GID (32 hex chars + null terminator).

    // Convert the port number to a string and store it in `service`.
    if (asprintf(&service, "%d", port) < 0)
        return NULL;

    // Step 1: Resolve the server's address using getaddrinfo().
    n = getaddrinfo(servername, service, &hints, &res);
    if (n < 0) {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(n), servername, port);
        free(service);
        return NULL;
    }

    // Step 2: Attempt to create a socket and connect to the server.
    for (t = res; t; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd >= 0) {
            if (!connect(sockfd, t->ai_addr, t->ai_addrlen))  // If connection succeeds, break the loop.
                break;
            close(sockfd);  // Close the socket if the connection fails and try the next address.
            sockfd = -1;
        }
    }

    freeaddrinfo(res);  // Free the address info structures.
    free(service);      // Free the service string.

    // Check if we failed to connect to the server.
    if (sockfd < 0) {
        fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        return NULL;
    }

    // Step 3: Convert my_dest's GID to wire format and prepare the message.
    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn, my_dest->psn, gid);

    // Send the local RDMA address information to the server.
    if (write(sockfd, msg, sizeof msg) != sizeof msg) {
        fprintf(stderr, "Couldn't send local address\n");
        goto out;
    }

    // Step 4: Read the remote RDMA address information from the server.
    if (read(sockfd, msg, sizeof msg) != sizeof msg) {
        perror("client read");
        fprintf(stderr, "Couldn't read remote address\n");
        goto out;
    }

    // Acknowledge the server with a "done" message.
    write(sockfd, "done", sizeof "done");

    // Step 5: Allocate memory for the remote destination structure.
    rem_dest = malloc(sizeof *rem_dest);
    if (!rem_dest)
        goto out;

    // Parse the received message into the remote destination structure.
    sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
    wire_gid_to_gid(gid, &rem_dest->gid);  // Convert the wire-format GID back to `ibv_gid`.

    out:
    close(sockfd);  // Close the socket.
    return rem_dest;  // Return the remote destination structure, or NULL on failure.
}


/**
 * pp_server_exch_dest - Establishes a server-side connection and exchanges RDMA destination info.
 * @ctx: The RDMA context containing QP, CQ, PD, etc.
 * @ib_port: The InfiniBand port to use for the connection.
 * @mtu: The MTU size for the RDMA connection.
 * @port: The TCP port number on which the server will listen for incoming connections.
 * @sl: The service level to be used for the RDMA connection.
 * @my_dest: A pointer to the pingpong_dest structure containing the local RDMA address info.
 * @sgid_idx: Index of the source GID (Global Identifier).
 *
 * This function sets up a TCP server that listens for incoming connections, accepts a connection,
 * and exchanges RDMA information (LID, QPN, PSN, GID) with the client.
 *
 * Steps:
 * 1. Resolves the server's address using `getaddrinfo`.
 * 2. Binds to the resolved address and listens for incoming TCP connections.
 * 3. Accepts a connection and reads the remote RDMA destination information from the client.
 * 4. Modifies the local Queue Pair (QP) to connect to the remote RDMA QP.
 * 5. Sends the local RDMA destination information to the client.
 *
 * Return:
 *   - A pointer to a `pingpong_dest` structure containing the remote destination information on success.
 *   - NULL on failure (e.g., if the connection fails, if memory allocation fails, or if the exchange of information fails).
 */
static struct pingpong_dest *pp_server_exch_dest(struct pingpong_context *ctx,
                                                 int ib_port, enum ibv_mtu mtu,
                                                 int port, int sl,
                                                 const struct pingpong_dest *my_dest,
                                                 int sgid_idx)
{
    struct addrinfo *res, *t;
    struct addrinfo hints = {
            .ai_flags    = AI_PASSIVE,    // Server mode: AI_PASSIVE is set to allow binding.
            .ai_family   = AF_INET,       // Use IPv4 addresses.
            .ai_socktype = SOCK_STREAM    // Use TCP sockets.
    };
    char *service;
    char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];  // Buffer to store RDMA info.
    int n;
    int sockfd = -1, connfd;
    struct pingpong_dest *rem_dest = NULL;
    char gid[33];  // Buffer for storing the GID in wire format (32 hex characters + null terminator).

    // Convert the port number to a string and store it in `service`.
    if (asprintf(&service, "%d", port) < 0)
        return NULL;

    // Step 1: Resolve the address for binding the server.
    n = getaddrinfo(NULL, service, &hints, &res);
    if (n < 0) {
        fprintf(stderr, "%s for port %d\n", gai_strerror(n), port);
        free(service);
        return NULL;
    }

    // Step 2: Create a socket, bind it to the address, and listen for incoming connections.
    for (t = res; t; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd >= 0) {
            n = 1;
            setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof n);  // Allow address reuse.

            if (!bind(sockfd, t->ai_addr, t->ai_addrlen))  // Successfully binded the socket.
                break;
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(res);  // Free the address info structures.
    free(service);      // Free the service string.

    if (sockfd < 0) {
        fprintf(stderr, "Couldn't listen to port %d\n", port);
        return NULL;
    }

    // Step 2 (continued): Listen for a single incoming connection.
    listen(sockfd, 1);
    connfd = accept(sockfd, NULL, 0);  // Accept the connection from the client.
    close(sockfd);                     // Close the listening socket.
    if (connfd < 0) {
        fprintf(stderr, "accept() failed\n");
        return NULL;
    }

    // Step 3: Read the remote RDMA destination information from the client.
    n = read(connfd, msg, sizeof msg);
    if (n != sizeof msg) {
        perror("server read");
        fprintf(stderr, "%d/%d: Couldn't read remote address\n", n, (int)sizeof msg);
        goto out;
    }

    // Allocate memory for the remote destination structure.
    rem_dest = malloc(sizeof *rem_dest);
    if (!rem_dest)
        goto out;

    // Parse the received message into the remote destination structure.
    sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
    wire_gid_to_gid(gid, &rem_dest->gid);  // Convert the wire-format GID to ibv_gid format.

    // Step 4: Connect the local QP to the remote QP.
    if (pp_connect_ctx(ctx, ib_port, my_dest->psn, mtu, sl, rem_dest, sgid_idx)) {
        fprintf(stderr, "Couldn't connect to remote QP\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

    // Step 5: Send the local RDMA destination information to the client.
    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn, my_dest->psn, gid);
    if (write(connfd, msg, sizeof msg) != sizeof msg) {
        fprintf(stderr, "Couldn't send local address\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

    // Wait for acknowledgment from the client.
    read(connfd, msg, sizeof msg);

    out:
    close(connfd);  // Close the connection socket.
    return rem_dest;  // Return the remote destination structure, or NULL on failure.
}


/**
 * pp_init_ctx - Initializes the RDMA context for the ping-pong test.
 * @ib_dev: Pointer to the RDMA device.
 * @size: The size of the memory buffer to be used for RDMA.
 * @rx_depth: The depth of the receive queue (number of receive work requests).
 * @tx_depth: The depth of the transmit queue (number of send work requests).
 * @port: The InfiniBand port number to use.
 * @use_event: Flag indicating whether to use completion events or polling.
 * @is_server: Flag to indicate whether the context is for the server (1) or client (0).
 *
 * This function performs the following steps:
 * 1. Allocates memory for the `pingpong_context` structure.
 * 2. Allocates a memory buffer for the RDMA operations.
 * 3. Opens the RDMA device context using `ibv_open_device`.
 * 4. Optionally creates a completion channel if events are to be used.
 * 5. Allocates a protection domain (PD) for the RDMA context.
 * 6. Registers a memory region (MR) for the allocated buffer.
 * 7. Creates a completion queue (CQ) for send and receive work requests.
 * 8. Creates a queue pair (QP) with the send and receive capabilities.
 * 9. Modifies the QP state to `INIT` to prepare it for further configuration.
 *
 * Return:
 *   - A pointer to the initialized `pingpong_context` structure on success.
 *   - NULL on failure, with appropriate error messages printed to `stderr`.
 */
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
                                            int rx_depth, int tx_depth, int port,
                                            int use_event, int is_server)
{
    struct pingpong_context *ctx;

    // Step 1: Allocate memory for the pingpong_context structure.
    ctx = calloc(1, sizeof *ctx);
    if (!ctx)
        return NULL;

    ctx->size     = size;       // Store the size of the buffer.
    ctx->rx_depth = rx_depth;   // Store the receive queue depth.
    ctx->routs    = rx_depth;   // Initialize routs (number of outstanding receives).

    // Step 2: Allocate a memory buffer for RDMA operations, rounded up to the page size.
    ctx->buf = malloc(roundup(size, page_size));
    if (!ctx->buf) {
        fprintf(stderr, "Couldn't allocate work buf.\n");
        return NULL;
    }

    // Initialize the buffer with a specific pattern based on whether it's for a server or client.
    memset(ctx->buf, 0x7b + is_server, size);  // '0x7b' is a starting value, modified by is_server.

    // Step 3: Open the RDMA device context.
    if (comp_context == NULL) {
        comp_context = ibv_open_device(ib_dev);
        if (!comp_context) {
            fprintf(stderr, "Couldn't get context for %s\n", ibv_get_device_name(ib_dev));
            return NULL;
        }
    }
    ctx->context = comp_context;

    // Step 4: Optionally create a completion channel if `use_event` is set.
    if (use_event) {
        ctx->channel = ibv_create_comp_channel(ctx->context);
        if (!ctx->channel) {
            fprintf(stderr, "Couldn't create completion channel\n");
            return NULL;
        }
    } else {
        ctx->channel = NULL;  // No event channel, use polling.
    }

    // Step 5: Allocate a protection domain (PD).
    if (comp_pd == NULL) {
        comp_pd = ibv_alloc_pd(ctx->context);
        if (!comp_pd) {
            fprintf(stderr, "Couldn't allocate PD\n");
            return NULL;
        }
    }
    ctx->pd = comp_pd;

    // OUR CODE ADDITIONS: IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ
    // Step 6: Register the memory region (MR) for the allocated buffer.
    ctx->mr = ibv_reg_mr(ctx->pd, ctx->buf, size, IBV_ACCESS_LOCAL_WRITE |
                                                    IBV_ACCESS_REMOTE_WRITE |
                                                    IBV_ACCESS_REMOTE_READ);
    if (!ctx->mr) {
        fprintf(stderr, "Couldn't register MR\n");
        return NULL;
    }

    // Step 7: Create a completion queue (CQ) for send and receive operations.
    ctx->cq = ibv_create_cq(ctx->context, rx_depth + tx_depth, NULL,
                                   ctx->channel, 0);
    if (!ctx->cq) {
        fprintf(stderr, "Couldn't create CQ\n");
        return NULL;
    }

    // Step 8: Create a Queue Pair (QP) with the appropriate attributes.
    {
        struct ibv_qp_init_attr attr = {
                .send_cq = ctx->cq,  // Associate send operations with the CQ.
                .recv_cq = ctx->cq,  // Associate receive operations with the CQ.
                .cap     = {
                        .max_send_wr  = tx_depth,    // Maximum number of outstanding send requests.
                        .max_recv_wr  = rx_depth,    // Maximum number of outstanding receive requests.
                        .max_send_sge = 1,           // Max scatter/gather entries per send.
                        .max_recv_sge = 1            // Max scatter/gather entries per receive.
                },
                .qp_type = IBV_QPT_RC        // Set the QP type to Reliable Connection (RC).
        };

        ctx->qp = ibv_create_qp(ctx->pd, &attr);  // Create the QP.
        if (!ctx->qp)  {
            fprintf(stderr, "Couldn't create QP\n");
            return NULL;
        }
    }

    // Step 9: Modify the QP state to `INIT` to prepare it for further transitions.
    {
        struct ibv_qp_attr attr = {
                .qp_state        = IBV_QPS_INIT,       // Set the QP state to INIT.
                .pkey_index      = 0,                  // P_Key index for partitioning.
                .port_num        = port,               // Associate the QP with the specified port.
                .qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
                                    IBV_ACCESS_REMOTE_READ |
                                    IBV_ACCESS_REMOTE_WRITE  // Allow remote read/write access.
        };

        // Modify the QP to INIT state.
        if (ibv_modify_qp(ctx->qp, &attr,
                          IBV_QP_STATE              |
                          IBV_QP_PKEY_INDEX         |
                          IBV_QP_PORT               |
                          IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Failed to modify QP to INIT\n");
            return NULL;
        }
    }

    // Return the initialized context.
    return ctx;
}

/**
 * pp_close_ctx - Cleans up and releases resources associated with the ping-pong context.
 * @ctx: Pointer to the `pingpong_context` structure to be cleaned up.
 *
 * This function performs the following steps in reverse order of initialization:
 * 1. Destroys the Queue Pair (QP).
 * 2. Destroys the Completion Queue (CQ).
 * 3. Deregisters the Memory Region (MR).
 * 4. Deallocates the Protection Domain (PD).
 * 5. Destroys the Completion Channel (if it exists).
 * 6. Closes the RDMA device context.
 * 7. Frees the allocated memory buffer and the `pingpong_context` structure itself.
 *
 * Return:
 *   - 0 on success.
 *   - 1 on failure, with appropriate error messages printed to `stderr`.
 */
int pp_close_ctx(struct pingpong_context *ctx)
{
    // Step 1: Destroy the Queue Pair (QP).
    if (ibv_destroy_qp(ctx->qp)) {
        fprintf(stderr, "Couldn't destroy QP\n");
        return 1;
    }

    // Step 2: Destroy the Completion Queue (CQ).
    if (ibv_destroy_cq(ctx->cq)) {
        fprintf(stderr, "Couldn't destroy CQ\n");
        return 1;
    }

    // Step 3: Deregister the Memory Region (MR).
    if (ibv_dereg_mr(ctx->mr)) {
        fprintf(stderr, "Couldn't deregister MR\n");
        return 1;
    }

    // Step 4: Deallocate the Protection Domain (PD).
    // There is only one PD for each computer, one PD for Server, one PD for a Client, this de-allocation happens once.
    if (ctx->pd != NULL) {
        if (ibv_dealloc_pd(ctx->pd)) {
            fprintf(stderr, "Couldn't deallocate PD\n");
            return 1;
        }
    }

    // Step 5: Destroy the Completion Channel, if it exists.
    if (ctx->channel) {
        if (ibv_destroy_comp_channel(ctx->channel)) {
            fprintf(stderr, "Couldn't destroy completion channel\n");
            return 1;
        }
    }

    // Step 6: Close the RDMA device context.
    if (ibv_close_device(ctx->context)) {
        fprintf(stderr, "Couldn't release context\n");
        return 1;
    }

    // Step 7: Free the allocated memory buffer and the pingpong_context structure.
    if (ctx->buf != NULL) {
        free(ctx->buf);
    }
    free(ctx);

    return 0;
}

/**
 * pp_post_recv - Posts receive work requests to the RDMA Queue Pair.
 * @ctx: Pointer to the pingpong_context structure that holds RDMA resources.
 * @n: Number of receive requests to post.
 *
 * This function constructs and posts `n` receive work requests to the QP.
 * Each work request specifies where the incoming data will be placed (buffer, length, and local key).
 * The receive work requests are used to receive messages in the RDMA communication.
 *
 * Return:
 *   - The number of successfully posted receive requests.
 *   - If an error occurs while posting a request, it returns the count of successfully posted requests up to that point.
 */
static int pp_post_recv(struct pingpong_context *ctx, int n)
{
    // Scatter-gather element (SGE) list that describes the receive buffer.
    struct ibv_sge list = {
            .addr   = (uintptr_t) ctx->buf,  // Starting address of the buffer.
            .length = ctx->size,             // Length of the buffer.
            .lkey   = ctx->mr->lkey          // Local key of the memory region.
    };

    // Receive work request (WR) that describes the operation to be performed.
    struct ibv_recv_wr wr = {
            .wr_id     = PINGPONG_RECV_WRID,  // Work Request ID for identifying the request.
            .sg_list   = &list,               // Scatter-gather list, which specifies the memory buffer.
            .num_sge   = 1,                   // Number of scatter-gather elements.
            .next      = NULL                 // This WR is not part of a linked list.
    };

    // Used to capture any bad work requests in case of failure.
    struct ibv_recv_wr *bad_wr;
    int i;

    // Loop to post `n` receive requests.
    for (i = 0; i < n; ++i) {
        // Post a recieve work request to the QP.
        // If the post fails, the loop breaks, and the function returns the number of successfully posted requests.
        if (ibv_post_recv(ctx->qp, &wr, &bad_wr))
            break;
    }

    // Return the number of successfully posted receive requests.
    return i;
}

/**
 * pp_post_send - Posts a send work request to the RDMA Queue Pair.
 * @ctx: Pointer to the pingpong_context structure that holds RDMA resources.
 *
 * This function constructs and posts a single send work request to the QP.
 * The work request specifies the data buffer to be sent and additional parameters for the send operation.
 *
 * Return:
 *   - 0 on success, or a negative value on failure.
 */
static int pp_post_send(struct pingpong_context *ctx)
{
    // Scatter-gather element (SGE) list that describes the send buffer.
    struct ibv_sge list = {
            .addr   = (uint64_t)ctx->buf,  // Starting address of the buffer.
            .length = ctx->size,            // Length of the buffer.
            .lkey   = ctx->mr->lkey         // Local key of the memory region.
    };

    // Send work request (WR) that describes the operation to be performed.
    struct ibv_send_wr *bad_wr, wr = {
            .wr_id     = PINGPONG_SEND_WRID,   // Work Request ID for identifying the request.
            .sg_list   = &list,                 // Scatter-gather list, which specifies the memory buffer.
            .num_sge   = 1,                     // Number of scatter-gather elements (1 for this request).
            .opcode     = IBV_WR_SEND,          // Operation type (send operation).
            .send_flags = IBV_SEND_SIGNALED,    // Indicates that the completion of this request should be signaled.
            .next       = NULL,                   // This WR is not part of a linked list.

            // Special additions for the RDMA Write operation
            .wr.rdma.remote_addr = 0, // Set remote address
            .wr.rdma.rkey        = 0         // Set remote key
    };

    // Post the send work request to the QP.
    return ibv_post_send(ctx->qp, &wr, &bad_wr);
}

/*static int pp_post_send_with_ack(struct pingpong_context *ctx, void *ack_buf, uint32_t ack_size, uint32_t ack_lkey)
{
    // Send work request (WR) that describes the operation to be performed.
    struct ibv_send_wr *bad_wr, wr = {
            .wr_id     = PINGPONG_SEND_WRID,   // Work Request ID for identifying the request.
            .sg_list   = &list,                 // Scatter-gather list, which specifies the memory buffer.
            .num_sge   = 1,                     // Number of scatter-gather elements (1 for this request).
            .opcode     = IBV_WR_SEND,          // Operation type (send operation).
            .send_flags = IBV_SEND_SIGNALED,    // Indicates that the completion of this request should be signaled.
            .next       = &wr_ack,                   // This WR is not part of a linked list.

            // Special additions for the RDMA Write operation
            .wr.rdma.remote_addr = 0, // Set remote address
            .wr.rdma.rkey        = 0         // Set remote key
    };

    // Post the send work request to the QP.
    return ibv_post_send(ctx->qp, &wr, &bad_wr);
}*/

/**
 * pp_wait_completions - Waits for the completion of a number of work requests.
 * @ctx: Pointer to the pingpong_context structure that holds RDMA resources.
 * @iters: The total number of work requests to wait for completions.
 *
 * This function polls the completion queue for completed work requests and processes them.
 *
 * Return:
 *   - 0 on success, or a non-zero value on failure.
 */
int pp_wait_completions(struct pingpong_context *ctx, int iters)
{
    int rcnt = 0, scnt = 0;  // Count of received and sent completions
    while (rcnt + scnt < iters) {  // Continue until all iterations are completed
        struct ibv_wc wc[WC_BATCH];  // Array for storing work completion records
        int ne, i;

        // Poll the completion queue for completed work requests
        do {
            ne = ibv_poll_cq(ctx->cq, WC_BATCH, wc);  // Poll for completions
            if (ne < 0) {
                fprintf(stderr, "poll CQ failed %d\n", ne);
                return 1;  // Return on failure
            }
        } while (ne < 1);  // Continue polling until at least one completion is received

        // Process the completions
        for (i = 0; i < ne; ++i) {
            if (wc[i].status != IBV_WC_SUCCESS) {  // Check for errors in completion status
                fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
                        ibv_wc_status_str(wc[i].status),
                        wc[i].status, (int) wc[i].wr_id);
                return 1;  // Return on failure
            }

            switch ((int) wc[i].wr_id) {  // Handle completions based on work request ID
                case PINGPONG_SEND_WRID:
                    ++scnt;  // Increment send completion count
                    break;

                case PINGPONG_RECV_WRID:
                    ++rcnt;  // Increment receive completion count/

                    if (--ctx->routs <= 10) {  // Check if it needs to post more receives
                        ctx->routs += pp_post_recv(ctx, ctx->rx_depth - ctx->routs);

                        if (ctx->routs < ctx->rx_depth) {
                            fprintf(stderr, "Couldn't post receive (%d)\n", ctx->routs);
                            return 1;  // Return on failure to post receive
                        }
                    }
                    break;

                default:
                    fprintf(stderr, "Completion for unknown wr_id %d\n", (int) wc[i].wr_id);
                    return 1;  // Return on unknown WR ID
            }
        }
    }
    return 0;  // Successful completion
}

static void usage(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s            start a server and wait for connection\n", argv0);
    printf("  %s <host>     connect to server at <host>\n", argv0);
    printf("\n");
    printf("Options:\n");
    printf("  -p, --port=<port>      listen on/connect to port <port> (default 18515)\n");
    printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
    printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
    printf("  -s, --size=<size>      size of message to exchange (default 4096)\n");
    printf("  -m, --mtu=<size>       path MTU (default 1024)\n");
    printf("  -r, --rx-depth=<dep>   number of receives to post at a time (default 500)\n");
    printf("  -n, --iters=<iters>    number of exchanges (default 1000)\n");
    printf("  -l, --sl=<sl>          service level value\n");
    printf("  -e, --events           sleep on CQ events (default poll)\n");
    printf("  -g, --gid-idx=<gid index> local port gid index\n");
}

// ------------------------------------------- Exercise 3 - Part 1 ------------------------------------------

static struct MR_place_pair empty_pair;

int init_empty_pair(void* kv_handle) {
    struct kv_handle *kv_handle_struct = (struct kv_handle *) kv_handle;

    empty_pair.value = malloc(sizeof(char));
    if (empty_pair.value == NULL) {
        return 1;
    }
    empty_pair.size = 1;
    empty_pair.mr = ibv_reg_mr(kv_handle_struct->ctx->pd,
                                empty_pair.value,
                                empty_pair.size,
                                IBV_ACCESS_LOCAL_WRITE |
                                IBV_ACCESS_REMOTE_WRITE |
                                IBV_ACCESS_REMOTE_READ);
    if (empty_pair.mr == NULL) {
        free(empty_pair.value);
        return 1;
    }

    strcpy(empty_pair.value, "\0");

    return 0;
}

static List_pairs *kv_store; // TODO create a full abstractions where the only things that the program does
                             //  is use a get/set operations with the kv_store without knowing what it is

int init_kv_store() {
    kv_store = malloc(sizeof(List_pairs));
    if (kv_store == NULL) {
        return 1;
    }
    kv_store->head = NULL;

    return 0;
}

// static struct list actions_database; // TODO

int kv_client_main(void *kv_handle);

// If new_size is big/small enough in comparison to old_size, will reallocate accordingly
int smart_realloc(void** data, int old_size, int new_size) {
    if (old_size <= 0 || new_size <= 0) {
        return 1;
    }

    if (new_size > old_size) {
        if ((*data) != NULL) {
            free((*data));
        }
    }
    else if (old_size > new_size*2) {
        if ((*data) != NULL) {
            free((*data));
        }

        (*data) = malloc(new_size * sizeof(char));
        if (*data == NULL) {
            // TODO free others
            return 1;
        }
        return 0;
    }

    return 1;
}

// pp_post_send but through RDMA Rendezvous, remote address and remote key
static int pp_post_send_RDMA(struct pingpong_context *ctx, const uint64_t remote_addr, const uint32_t rkey,
        enum ibv_wr_opcode opcode, void* ack_buf, uint32_t ack_size, uint32_t ack_lkey)
{
    // Scatter-gather element (SGE) list that describes the send buffer.
    struct ibv_sge list_ack = {
            .addr   = (uint64_t) ack_buf,  // Starting address of the buffer.
            .length = ack_size,            // Length of the buffer.
            .lkey   = ack_lkey         // Local key of the memory region.
    };

    // Send work request (WR) that describes the operation to be performed.
    struct ibv_send_wr *bad_wr_ack, wr_ack = {
            .wr_id     = PINGPONG_SEND_WRID,   // Work Request ID for identifying the request.
            .sg_list   = &list_ack,                 // Scatter-gather list, which specifies the memory buffer.
            .num_sge   = 1,                     // Number of scatter-gather elements (1 for this request).
            .opcode     = IBV_WR_SEND,          // Operation type (send operation).
            .send_flags = IBV_SEND_SIGNALED,    // Indicates that the completion of this request should be signaled.
            .next       = NULL,                   // This WR is not part of a linked list.

            // Special additions for the RDMA Write operation
            .wr.rdma.remote_addr = 0, // Set remote address
            .wr.rdma.rkey        = 0         // Set remote key
    };

    struct ibv_send_wr wr;
    struct ibv_sge list;
    struct ibv_send_wr *bad_wr = NULL;

    /* prepare the scatter/gather entry */
    memset(&list, 0, sizeof(list));
    list.addr = (uint64_t)ctx->buf;
    list.length = ctx->size;
    list.lkey = ctx->mr->lkey;

    /* prepare the send work request */
    memset(&wr, 0, sizeof(wr));

    wr.next = &wr_ack;
    wr.wr_id = PINGPONG_RDMA_OP;
    wr.sg_list = &list;
    wr.num_sge = 1;
    // opcode == IBV_WR_RDMA_WRITE || opcode == IBV_WR_RDMA_READ
    wr.opcode = opcode;
    wr.send_flags = IBV_SEND_SIGNALED;

    // Special additions for the RDMA Write operation
    wr.wr.rdma.remote_addr = remote_addr; // Set remote address
    wr.wr.rdma.rkey        = rkey;         // Set remote key

    return ibv_post_send(ctx->qp, &wr, &bad_wr);
}

// Generates a random string of size in bytes
void generate_random_string(char *str, size_t size) {
    if (size < 1 && str != NULL) {
        // Size must be at least 1 to store the null terminator
        return;
    }

    // Printable characters
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?";
    size_t charset_size = sizeof(charset) - 1;  // Size of the charset, excluding null terminator

    for (size_t i = 0; i < size - 1; i++) {
        int random_index = rand() % charset_size;
        str[i] = charset[random_index];
    }

    str[size - 1] = '\0';  // Null-terminate the string
}

void get_first_word(const char *str, char *first_word) {
    if (str == NULL || first_word == NULL) {
        return;
    }

    int i = 0;
    // Skip leading spaces
    while (isspace(str[i])) {
        i++;
    }

    // Copy characters until a space or end of string
    int j = 0;
    while (str[i] != '\0' && !isspace(str[i])) {
        first_word[j++] = str[i++];
    }

    // Null-terminate the first word
    first_word[j] = '\0';
}

// TODO these two functions, if return 1, cant be distinguished from non-error?
// Receives string of a number and returns it in the form of an uint64_t
uint64_t get_str_uint64_t(const char *str) {
    char *endptr;

    // Convert string to uint64_t
    uint64_t value = strtoull(str, &endptr, 10);  // Base 10 for decimal conversion

    // Check if the conversion was successful
    if (endptr == str) {
        printf("Conversion failed, no digits found\n");
        return 1;
    } else if (*endptr != '\0') {
        printf("Conversion stopped at: %s\n", endptr);  // Handle remaining characters in string
        return 1;
    } else {
        return value;
    }
}

// Receives string of a number and returns it in the form of an uint32_t
uint32_t get_str_uint32_t(const char *str) {
    char *endptr;

    // Convert string to unsigned long with base 10 (decimal)
    unsigned long value = strtoul(str, &endptr, 10);

    // Error checking: If no digits were found, or if the value is out of bounds
    if (endptr == str) {
        printf("Conversion failed, no digits found\n");
        return 0;
    }

    if (value > UINT32_MAX) {
        printf("Value out of range for uint32_t\n");
        return 0;
    }

    return (uint32_t)value;
}

// Prints out the KV store of the given kv_handle
void print_kv_store(struct kv_handle* cur_kv_handle) {
    if (cur_kv_handle == NULL) {
        return;
    }
    if (count_nodes_pairs(kv_store) <= 0) {
        printf("Nothing to print in KV Store\n");
        return;
    }

    printf("--------------------\n");
    printf("Printing KV store:\n");

    int i = 0;
    for (Node_pairs* cur_node = kv_store->head; cur_node != NULL; cur_node = cur_node->next) {
        printf("item number: %d For key %.30s\n", i, cur_node->key);
        printf("Value of size: %zu\n", strlen(cur_node->pair->value));
        printf("value: %.30s\n", cur_node->pair->value);

        i++;
    }

    printf("--------------------\n");
}

Node_pairs* create_value_size_by_key(void* kv_handle, const char* key, int value_size) {
    if (kv_handle == NULL || key == NULL || value_size <= 0)
        return NULL;

    struct kv_handle *kv_handle_struct = (struct kv_handle *) kv_handle;

    char* new_val = malloc(value_size * sizeof(char));
    if (new_val == NULL) {
        printf("malloc failed on making new value size-based pair in kv_store\n");
        return NULL;
    }
    struct ibv_mr* new_mr = ibv_reg_mr(kv_handle_struct->ctx->pd,
                                       new_val,
                                       value_size,
                                       IBV_ACCESS_LOCAL_WRITE |
                                       IBV_ACCESS_REMOTE_WRITE |
                                       IBV_ACCESS_REMOTE_READ);

    if (new_mr == NULL) {
        printf("mr reg failed on making new value size-based pair in kv_store\n");
        free(new_val);
        return NULL;
    }

    Node_pairs* cur_node = find_pairs(key, kv_store);

    if (cur_node) {
        if (cur_node->pair != NULL) {
            // Freeing and reallocating a relevant MR for the new value
            if (cur_node->pair->value != NULL) {
                free(cur_node->pair->value);
            }
            if (cur_node->pair->mr != NULL) {
                ibv_dereg_mr(cur_node->pair->mr);
            }
        }
        else {
            cur_node->pair = malloc(sizeof(struct MR_place_pair));
            if (cur_node->pair == NULL) {
                // TODO free others
                return NULL;
            }
        }

        cur_node->pair->size = value_size;
        cur_node->pair->value = new_val;
        cur_node->pair->mr = new_mr;
    }
    else {
        struct MR_place_pair* new_pair = malloc(sizeof(struct MR_place_pair));
        if(new_pair == NULL) {
            // TODO free and dereg the others
            return NULL;
        }

        new_pair->value = new_val;
        new_pair->mr = new_mr;

        cur_node = add_pairs(key, new_pair, kv_store);
        if (cur_node == NULL) {
            // TODO free and dereg the others
            return NULL;
        }
    }

    return cur_node;
}

// Sets the MR place pair of the given key-value pair in the kv_store
// If the key exists in the store, frees the previous and sets the new one up.
// Creates a new kv pair if it doesn't exist already
// Used for Rendezvous cases
Node_pairs* set_MR_pair_by_key(void* kv_handle, const char* key, struct MR_place_pair* MR_pair) {
    if (kv_handle == NULL || key == NULL || MR_pair == NULL)
        return NULL;

    Node_pairs* cur_node = find_pairs(key, kv_store);
    if (cur_node != NULL) {
        // TODO note the big todo in the set value by key func below
        // TODO lots of similar code as below func
        // Destroying the previous pair if it exists
        if (cur_node->pair != NULL) {
            if (cur_node->pair == MR_pair) {
                return cur_node;
            }

            // Freeing and reallocating a relevant MR for the new value
            if (cur_node->pair->value != NULL) {
                free(cur_node->pair->value);
            }
            if (cur_node->pair->mr != NULL) {
                ibv_dereg_mr(cur_node->pair->mr);
            }

            free(cur_node->pair);
        }

        cur_node->pair = MR_pair;
    }
    else {
        cur_node = add_pairs(key, MR_pair, kv_store);
        if (cur_node == NULL) {
            return NULL;
        }
    }

    return cur_node;
}

// Used for Eager cases
Node_pairs* set_value_by_key(void* kv_handle, const char* key, const char* value) {
    if (kv_handle == NULL || key == NULL || value == NULL)
        return NULL;

    struct kv_handle *kv_handle_struct = (struct kv_handle *) kv_handle;

    Node_pairs* cur_node = find_pairs(key, kv_store);
    if (cur_node != NULL) {
        // TODO do we make an entirely new value malloc and mr for each set or check the
        //  size before hand and change the contents? if we change only the contents,
        //  we might get stuck with a pointer in a race condition problem, better to make a new pointer all the time no?
        //  should we free the old pointer in such case??
        //  maybe the ACK after RDMA will replace the pointer into place??
        //  POST HAGASHA MAIN PROBLEM HERE ^^^^^
        //  for now, we will free and remake the malloc and mr

        // TODO ALOT OF REPEATED CODE HERE AS CREATE FUNC RIGHT ABOVE
        if (cur_node->pair != NULL) {
            // Freeing and reallocating a relevant MR for the new value
            if (cur_node->pair->value != NULL) {
                free(cur_node->pair->value);
            }
            if (cur_node->pair->mr != NULL) {
                ibv_dereg_mr(cur_node->pair->mr);
            }
        }
        else {
            cur_node->pair = malloc(sizeof(struct MR_place_pair));
            if (cur_node->pair == NULL) {
                // TODO FREE AND DEREG OTHERS
                return NULL;
            }
        }

        int value_size = (int) strlen(value) + 1;
        char* new_val = malloc(value_size * sizeof(char));
        if (new_val == NULL) {
            printf("malloc failed on making new value size-based pair in kv_store\n");
            return NULL;
        }
        struct ibv_mr* new_mr = ibv_reg_mr(kv_handle_struct->ctx->pd,
                                           new_val,
                                           value_size,
                                           IBV_ACCESS_LOCAL_WRITE |
                                           IBV_ACCESS_REMOTE_WRITE |
                                           IBV_ACCESS_REMOTE_READ);
        if (new_mr == NULL) {
            printf("mr reg failed on making new value size-based pair in kv_store\n");
            free(new_val);
            return NULL;
        }

        cur_node->pair->size = value_size;
        cur_node->pair->value = new_val;
        cur_node->pair->mr = new_mr;
    }
    else {
        cur_node = create_value_size_by_key(kv_handle, key, (int) strlen(value));
        if (!cur_node) {
            return NULL;
        }
    }

    strcpy(cur_node->pair->value, value);

    return cur_node;
}

struct MR_place_pair* get_value_by_key(void* kv_handle, const char* key) {
    if (kv_handle == NULL || key == NULL)
        return NULL;

    struct MR_place_pair* ret_pair = NULL;

    Node_pairs* cur_node = find_pairs(key, kv_store);
    if (cur_node == NULL) {
        printf("Couldn't find a corresponding key in the kv_store\n");
        ret_pair = &empty_pair;
    }
    else {
        ret_pair = cur_node->pair;

        // If there is a node without a corresponding value, we need to delete it from the kv_store
        if (!cur_node->pair) {
            delete_pairs(key, kv_store);
            ret_pair = &empty_pair;
        }
    }

    return ret_pair;
}

// Creates an empty, allocated MR place pair of size value_size
struct MR_place_pair* create_MR_place_pair_by_size(void* kv_handle, int value_size) { // TODO use this func instead of factory
    struct MR_place_pair* ret_MR_pair = malloc(sizeof(struct MR_place_pair));
    if (ret_MR_pair == NULL) {
        return NULL;
    }

    struct kv_handle *kv_handle_struct = (struct kv_handle *) kv_handle;

    char* new_val = malloc(value_size * sizeof(char));
    if (new_val == NULL) {
        printf("malloc failed on making new value size-based pair in kv_store\n");
        return NULL;
    }
    struct ibv_mr* new_mr = ibv_reg_mr(kv_handle_struct->ctx->pd,
                                       new_val,
                                       value_size,
                                       IBV_ACCESS_LOCAL_WRITE |
                                       IBV_ACCESS_REMOTE_WRITE |
                                       IBV_ACCESS_REMOTE_READ);

    if (new_mr == NULL) {
        printf("mr reg failed on making new value size-based pair in kv_store\n");
        free(new_val);
        return NULL;
    }

    ret_MR_pair->size = value_size;
    ret_MR_pair->value = new_val;
    ret_MR_pair->mr = new_mr;

    return ret_MR_pair;
}

// Used to reallocate or fully destroy an MR_place_pair
// If new_size<0, will destroy but will not reallocate
int MR_pair_factory(void* kv_handle, struct MR_place_pair* cur_pair, int new_size) {
    if (cur_pair == NULL || kv_handle == NULL) {
        return 1;
    }

    struct kv_handle* kv_handle_struct = (struct kv_handle*) kv_handle;

    bool change_needed = false;

    if (new_size > cur_pair->size) {
        change_needed = true;
    }
    else if (cur_pair->size > new_size*2) {
        change_needed = true;
    }


    if (change_needed || new_size < 0) {
        if (cur_pair->value != NULL) {
            free(cur_pair->value);
        }
        if(cur_pair->mr != NULL) {
            if (ibv_dereg_mr(cur_pair->mr)) {
                free(cur_pair->value);
                printf("Failed to deregister MR\n");
                return 1;
            }
        }

        cur_pair->size = 0;

        if (new_size >= 0) {
            cur_pair->value = malloc(new_size * sizeof(char));
            if (cur_pair->value == NULL) {
                return 1;
            }

            cur_pair->mr = ibv_reg_mr(kv_handle_struct->ctx->pd,
                                      cur_pair->value,
                                      new_size,
                                      IBV_ACCESS_LOCAL_WRITE |
                                      IBV_ACCESS_REMOTE_WRITE |
                                      IBV_ACCESS_REMOTE_READ);
            if (cur_pair->mr == NULL) {
                free(cur_pair->value);
                return 1;
            }

            cur_pair->size = new_size;
        }
    }

    return 0;
}

// Registers a Memory Region and allocates the appropriate amount according to the given size, in the kv_store
struct MR_place_pair* RDMA_register(void* kv_handle, const char* value, const char* key, int value_size) {
    if (kv_handle == NULL || key == NULL)
        return NULL;

    struct kv_handle *kv_handle_struct = (struct kv_handle *) kv_handle;

    /*int i;
    for (i = 0; i < MAX_KEYS; i++) {
        if (strcmp(kv_store[i].key, key) == 0) {
            break;
        }
    }*/

    // TODO
    Node_pairs* cur_node = find_pairs(key, kv_store);
    if (cur_node != NULL) {

    }
    else {

    }

    /*// If no relevant key was found, need to create a new key
    if (i >= kv_count) {
        // A new key position
        i = kv_count;

        // Check if there are too many keys as-is
        if (i >= MAX_KEYS) {
            i = 0;
        }
        // Adding another key-value to the count, if there is still a place in the total MAX KEYS pairs in the store
        else {
            kv_count++;
        }

        // Copying the appropriate key
        strcpy(kv_store[i].key, key);
    }

    // Creating/Recreating the MR place pair
    if (kv_store[i].place_pair == NULL) {
        kv_store[i].place_pair = malloc(sizeof(struct MR_place_pair));
        kv_store[i].place_pair->size = 1;

        kv_store[i].place_pair->value = malloc(sizeof(char));

        kv_store[i].place_pair->mr = ibv_reg_mr(kv_handle_struct->ctx->pd,
                                                                  kv_store[i].place_pair->value,
                                                                  1,
                                                                 IBV_ACCESS_LOCAL_WRITE |
                                                                 IBV_ACCESS_REMOTE_WRITE |
                                                                 IBV_ACCESS_REMOTE_READ);
        strcpy(kv_store[i].place_pair->value, ""); // Default value
        if (kv_store[i].place_pair->mr == NULL) {
            free(kv_store[i].place_pair->value);
            return NULL;
        }
    }

    if (MR_pair_factory(kv_handle, kv_store[i].place_pair, value_size)) {
        printf("Failed to create/recreate MR place pair");
        return NULL;
    }

    // Jonathan Notice: ibv_reg_mr destroys the data place pointer given to it, so it requires rewriting like this
    if (value != NULL) {
        strcpy(kv_store[i].place_pair->value, value);
    }

    // We do not free the "value" pointer here as it is not the responsibility of the function
    return kv_store[i].place_pair;*/
}

int send_msg(void *kv_handle, char* request, int size) {
    if (kv_handle == NULL || request == NULL || size <= 0) {
        return 1;
    }

    struct kv_handle *kv_handle_struct = (struct kv_handle *) kv_handle;

    kv_handle_struct->ctx->buf = kv_handle_struct->default_send_buf.value;
    kv_handle_struct->ctx->mr = kv_handle_struct->default_send_buf.mr;

    strcpy(kv_handle_struct->ctx->buf, request);

    // Send request to the server
    kv_handle_struct->ctx->size = size;
    if (pp_post_send(kv_handle_struct->ctx)) {
        fprintf(stderr, "Couldn't post send\n"); // Error handling
        return 1;
    }

    return 0;
}

int pp_wait_completions_split(void* kv_handle, int iters, const char* servername, char* request, char** value,
                              int num_of_connections);

// The Server receives a message and deconstructs it according to who got it. Calls the next operations as needed.
// The types of messages the server can get are:
// 1. GET "key"
// 2. SET "key" "value"
// 3. RDMA_SET "key" "value size"
// 4. RDMA_MR "key" "remote_address" "rkey"
// 5. ACK // TODO add key here??
// 6. PRINT_KV
// 7. WARMUP
int breakup_string_msg_server(char *msg, struct kv_handle *kv_handle_struct) {
    char *token = NULL;

    // Use strtok to get the first word
    token = strtok(msg, " ");  // Tokenize based on space
    if (token == NULL) {
        return 1;
    }

    // Check if the first word is "SET"
    if (strcmp(token, SET_MSG) == 0) {
        //printf("%s %s %s\n", SERVER_PREFIX, FIRST_WORD, SET_MSG);

        // Get the second part (key)
        char *cur_key = strtok(NULL, " ");

        // Get the third part (value)
        char *cur_value = strtok(NULL, " ");

        if (cur_key && cur_value) {
            Node_pairs* cur_node = set_value_by_key(kv_handle_struct, cur_key, cur_value);
            if (cur_node == NULL) {
                printf("Couldn't set a value in the kv_store for the SET operation on the SERVER\n");
                return 1;
            }

            // TODO does SET_ACK include a key?
            char request[8] = SET_ACK_MSG;
            if (send_msg(kv_handle_struct, request, (int) strlen(request) + 1)) {
                return 1;
            }
        } else {
            printf("%s %s\n", SERVER_PREFIX, INVALID_INPUT);
            return 1;
        }
    }
    else if (strcmp(token, GET_MSG) == 0) {
        //printf("%s %s %s\n", SERVER_PREFIX, FIRST_WORD, GET_MSG);

        // Get the second part (key)
        char *cur_key = strtok(NULL, " ");

        if (cur_key) {
            struct MR_place_pair *MR_pair = get_value_by_key(kv_handle_struct, cur_key);
            if (MR_pair == NULL) {
                printf("Did not find the MR pair for given key\n");
                return 1;
            }

            size_t value_len = strlen(MR_pair->value) + 1;
            size_t key_len = strlen(cur_key);

            // Two options from here:
            // 1. either the value is too big, thus needing to send back an RDMA request
            // 2. It is small enough to send the whole value in a single message

            char request[MAX_KEY_SIZE];
            if (value_len + key_len > MAX_KEY_SIZE) {
                snprintf(request, sizeof(request), "%s %s %zu %"PRIx64" %"PRIu32"", RDMA_READ_MR_MSG,
                         cur_key, value_len, (uintptr_t) MR_pair->mr->addr, MR_pair->mr->rkey);

                if (send_msg(kv_handle_struct, request, (int) strlen(request)+1)) {
                    return 1;
                }
            }
            else {
                snprintf(request, sizeof(request), "%s %s", GET_ACK_MSG, MR_pair->value);

                if (send_msg(kv_handle_struct, request, (int) strlen(request) + 1)) {
                    return 1;
                 }
            }

        } else {
            printf("%s %s\n", SERVER_PREFIX, INVALID_INPUT);
            return 1;
        }
    }
    else if (strcmp(token, RDMA_SET_MSG) == 0) {
        //printf("%s %s %s\n", SERVER_PREFIX, FIRST_WORD, RDMA_SET_MSG);

        // Get the second part (key)
        char *cur_key = strtok(NULL, " ");

        // Get the third part (value)
        char *value_size = strtok(NULL, " ");

        if (cur_key && value_size) {

            // Getting numerical value of value size
            uint32_t value_size_num = get_str_uint32_t(value_size); // TODO should be int? see below tih mr register

            // TODO later, go over CQ for more messages to post send before registering for efficiency's sake
            // Registering MR and allocating memory for it
            Node_pairs *cur_node = create_value_size_by_key(kv_handle_struct, cur_key, (int) value_size_num);
            if (cur_node == NULL) {
                return 1;
            }

            char request[MAX_KEY_SIZE];
            snprintf(request, sizeof(request), "%s %s %"PRIx64" %"PRIx64" %"PRIu32"",
                     RDMA_WRITE_MR_MSG, cur_key, (uintptr_t) cur_node->pair,
                     (uintptr_t) cur_node->pair->mr->addr, cur_node->pair->mr->rkey);
            if (send_msg(kv_handle_struct, request, (int) strlen(request) + 1)) {
                return 1;
            }
        } else {
            printf("%s %s\n", SERVER_PREFIX, INVALID_INPUT);
            return 1;
        }
    }
    else if (strcmp(token, RDMA_WRITE_ACK_MSG) == 0) {
        // Get the second part (key)
        char *cur_key = strtok(NULL, " ");

        // Get the third part (local MR pointer)
        char *local_MR_pointer = strtok(NULL, " ");

        // Get the fourth part (local pointer)
        char *local_pointer = strtok(NULL, " ");

        if (cur_key && local_MR_pointer && local_pointer) {
            // Getting the real value of the local pointer(as a pointer)
            void *local_addr = NULL;
            if (sscanf(local_pointer, "%p", &local_addr) != 1) {
                return 1;
            }

            // Getting the real value of the local MR pointer(as a pointer)
            struct MR_place_pair *local_MR_addr = NULL;
            if (sscanf(local_MR_pointer, "%p", &local_MR_addr) != 1) {
                return 1;
            }

            struct node_pairs* cur_node = set_MR_pair_by_key(kv_handle_struct, cur_key,
                                                             local_MR_addr);
            if (cur_node == NULL) {
                // TODO free others
                return 1;
            }
        }

        //printf("%s %s %s\n", SERVER_PREFIX, FIRST_WORD, RDMA_ACK_MSG);
    }
    else if (strcmp(token, RDMA_READ_ACK_MSG) == 0) {
        // Get the second part (key)
        char *cur_key = strtok(NULL, " ");

        if (cur_key) {
            printf("Successfully finished RDMA READ operation from key %s\n", cur_key);
        }

        //printf("%s %s %s\n", SERVER_PREFIX, FIRST_WORD, RDMA_ACK_MSG);
    }
    else if (strcmp(token, PRINT_KV_MSG) == 0) {
        //printf("%s %s %s\n", SERVER_PREFIX, FIRST_WORD, PRINT_KV_MSG);
        print_kv_store(kv_handle_struct);
    }
    else if (strcmp(token, WARMUP_MSG) == 0) {
        //printf("%s %s %s\n", SERVER_PREFIX, FIRST_WORD, WARMUP_MSG);
        return 0;
    }
    else {
        printf("%s The first word is not valid\n", SERVER_PREFIX);
        return 1;
    }

    return 0; // Success
}

// A Client receives a message and deconstructs it according to who got it. Calls the next operations as needed.
// The types of messages the client can get are:
// 1. GET_ACK "value"
// 2. SET_ACK
// 3. RDMA_SET "key" "value size"
// 4. RDMA_MR "key" "remote_address" "rkey"
// 5. ACK // TODO add key here??
int breakup_string_msg_client(char *msg, struct kv_handle *kv_handle_struct, char** value) {
    char *token = NULL;

    // Use strtok to get the first word
    token = strtok(msg, " ");  // Tokenize based on space
    if (token == NULL) {
        return 1;
    }

    // Check if the first word is "GET_ACK"
    if (strcmp(token, GET_ACK_MSG) == 0) {
        if (value == NULL) {
            printf("Memory space is unallocated\n");
            return 1;
        }
        if (*value == NULL) {
            printf("Memory space is unallocated in pointer\n");
            return 1;
        }

        // printf("%s %s %s\n", CLIENT_PREFIX, FIRST_WORD, GET_ACK_MSG);

        // Get the second part (value)
        char *cur_value = strtok(NULL, " ");
        if (cur_value == NULL) {
            return 1;
        }

        if (value == NULL || *value == NULL) {
            printf("Value provided is NULL, allocating appropriate memory space\n");
            *value = malloc(strlen(cur_value) * sizeof(char) + 1);
            if (*value == NULL) {
                return 1;
            }
        }

        strcpy(*value, cur_value);
    }
    else if (strcmp(token, SET_ACK_MSG) == 0) {
        // printf("%s %s %s\n", CLIENT_PREFIX, FIRST_WORD, SET_ACK_MSG);
    }
    else if (strcmp(token, RDMA_WRITE_MR_MSG) == 0) {
        // printf("%s %s %s\n", CLIENT_PREFIX, FIRST_WORD, RDMA_MR_MSG);

        // Get the current key
        char *cur_key = strtok(NULL, " ");

        // Get the remote MR_pair pointer
        char *rem_MR_pointer_str = strtok(NULL, " ");

        // Get the remote address
        char *remote_addr_str = strtok(NULL, " ");

        // Get the rkey
        char *rkey_str = strtok(NULL, " ");

        if (cur_key && rem_MR_pointer_str && remote_addr_str && rkey_str) {
            // Getting the real value of the rkey
            uint32_t rkey = get_str_uint32_t(rkey_str);

            // Getting the real value of the remote address(as a pointer)
            void *remote_addr = NULL;
            if (sscanf(remote_addr_str, "%p", &remote_addr) != 1) {
                return 1;
            }

            // Getting the real value of the remote MR pair pointer
            void *rem_MR_pointer = NULL;
            if (sscanf(rem_MR_pointer_str, "%p", &rem_MR_pointer) != 1) {
                return 1;
            }

            struct MR_place_pair *MR_pair = get_value_by_key(kv_handle_struct, cur_key);
            if (MR_pair == NULL) {
                printf("Did not find the MR pair for given key\n");
                return 1;
            }

            kv_handle_struct->ctx->size = (int) (strlen(MR_pair->value)) + 1;
            kv_handle_struct->ctx->buf = MR_pair->value;
            kv_handle_struct->ctx->mr = MR_pair->mr;

            // Creating the RDMA ack that goes along with the RDMA operation
            char* ack_buf = (char *) kv_handle_struct->default_send_buf.value;
            snprintf(ack_buf, MAX_KEY_SIZE, "%s %s %"PRIx64" %"PRIx64"", RDMA_WRITE_ACK_MSG,
                     cur_key, (uintptr_t) rem_MR_pointer, (uintptr_t) remote_addr);

            if (pp_post_send_RDMA(kv_handle_struct->ctx, (uintptr_t) remote_addr, rkey,
                                  IBV_WR_RDMA_WRITE, ack_buf, MAX_KEY_SIZE,
                                  kv_handle_struct->default_send_buf.mr->lkey)) {
                fprintf(stderr, "Couldn't post send RDMA\n"); // Error handling
                return 1;
            }
        } else {
            printf("%s %s\n", SERVER_PREFIX, INVALID_INPUT);
            return 1;
        }
    }
    else if (strcmp(token, RDMA_READ_MR_MSG) == 0) {
        // printf("%s %s %s\n", CLIENT_PREFIX, FIRST_WORD, RDMA_MR_MSG);

        // Get the current key
        char *cur_key = strtok(NULL, " ");

        // Get size of value that needs to be read from server pointer
        char *value_size = strtok(NULL, " ");

        // Get the remote address
        char *remote_addr_str = strtok(NULL, " ");

        // Get the rkey
        char *rkey_str = strtok(NULL, " ");

        if (cur_key && value_size && remote_addr_str && rkey_str) {
            // Getting the value size
            uint32_t value_size_num = get_str_uint32_t(value_size);

            // Getting the real value of the rkey
            uint32_t rkey = get_str_uint32_t(rkey_str);

            // Getting the real value of the remote address(as a pointer)
            void *remote_addr = NULL;
            if (sscanf(remote_addr_str, "%p", &remote_addr) != 1) {
                return 1;
            }

            // Registering MR and allocating memory for it
            Node_pairs* cur_node = create_value_size_by_key(kv_handle_struct, cur_key,
                                                            (int) value_size_num + 1);
            if (cur_node == NULL) {
                return 1;
            }

            kv_handle_struct->ctx->size = (int) value_size_num;
            kv_handle_struct->ctx->buf = cur_node->pair->value;
            kv_handle_struct->ctx->mr = cur_node->pair->mr;

            // Creating the RDMA ack that goes along with the RDMA operation
            char* ack_buf = (char *) kv_handle_struct->default_send_buf.value;
            snprintf(ack_buf, MAX_KEY_SIZE, "%s %s", RDMA_READ_ACK_MSG, cur_key);

            if (pp_post_send_RDMA(kv_handle_struct->ctx, (uintptr_t) remote_addr, rkey,
                                  IBV_WR_RDMA_READ, ack_buf, MAX_KEY_SIZE,
                                  kv_handle_struct->default_send_buf.mr->lkey)) {
                fprintf(stderr, "Couldn't post send RDMA\n"); // Error handling
                return 1;
            }
        } else {
            printf("%s %s\n", SERVER_PREFIX, INVALID_INPUT);
            return 1;
        }
    }
    else {
        printf("The first word is not valid\n");
        return 1;
    }

    return 0; // Success
}


// Like pp_wait_completions but takes into account whether it is a Server or a Client
// For Exercise 3
int pp_wait_completions_split(void* kv_handle, int iters, const char* servername, char* request,
                              char** value, int num_of_connections)
{
    if (iters <= 0) {
        return 0;
    }

    struct kv_handle *kv_handle_structs = (struct kv_handle *) kv_handle;
    for (int i = 0; i < num_of_connections; i++) {
        kv_handle_structs[i].ctx->buf = kv_handle_structs[i].default_recv_buf.value;
        kv_handle_structs[i].ctx->mr = kv_handle_structs[i].default_recv_buf.mr;
    }

    int rcnt = 0, scnt = 0, srdmacnt = 0;  // Count of received and sent completions
    while (rcnt + scnt + srdmacnt < iters) {  // Continue until all iterations are completed
        struct ibv_wc wc[WC_BATCH];  // Array for storing work completion records
        int ne, i;

        int current_ctx_ind = 0;
        // Poll the completion queue for completed work requests
        do {
            for (int j = 0; j < num_of_connections; j++) {
                ne = ibv_poll_cq(kv_handle_structs[j].ctx->cq, WC_BATCH, wc);  // Poll for completions
                if (ne < 0) {
                    fprintf(stderr, "poll CQ failed %d\n", ne);
                    return 1;  // Return on failure
                }
                if (ne >= 1) {
                    current_ctx_ind = j;
                    break;
                }
            }
        } while (ne < 1);  // Continue polling until at least one completion is received

        // Process the completions
        for (i = 0; i < ne; ++i) {
            if (wc[i].status != IBV_WC_SUCCESS) {  // Check for errors in completion status
                fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
                        ibv_wc_status_str(wc[i].status),
                        wc[i].status, (int) wc[i].wr_id);
                return 1;  // Return on failure
            }

            switch ((int) wc[i].wr_id) {  // Handle completions based on work request ID
                case PINGPONG_SEND_WRID:
                    ++scnt;  // Increment send completion count

                    if (PRINT_MSGS) {
                        printf("Sending message: %.25s ",
                               (char *) kv_handle_structs[current_ctx_ind].default_send_buf.value);
                        if (!servername) {
                            printf(" | to Client: %d ", current_ctx_ind);
                        }
                        printf("\n");
                    }



                    // TODO make into fnction
                    char* msg = (char *) kv_handle_structs[current_ctx_ind].default_send_buf.value;
                    char *token = NULL;

                    // Use strtok to get the first word
                    token = strtok(msg, " ");  // Tokenize based on space
                    if (token == NULL) {
                        return 1;
                    }

                    if (strcmp(token, RDMA_READ_ACK_MSG) == 0) {
                        // Get the second part (key)
                        char *cur_key = strtok(NULL, " ");

                        if (cur_key) {
                            struct MR_place_pair* cur_MR = get_value_by_key(kv_handle, cur_key);
                            if (cur_MR == NULL) {
                                printf("Error retrieving recent RDMA READ value for key %.30s\n", cur_key);
                                return 1;
                            }
                            printf("For Key: %.30s | Value gotten from RDMA READ operation: %.30s\n", cur_key, cur_MR->value);
                        }
                    }

                    break;

                case PINGPONG_RECV_WRID:
                    ++rcnt;  // Increment receive completion count
                    if (PRINT_MSGS) {
                        printf("Receiving message: %.25s ",
                               (char *) kv_handle_structs[current_ctx_ind].default_recv_buf.value);
                        if (!servername) {
                            printf(" | from Client: %d ", current_ctx_ind);
                        }
                        printf("\n");
                    }

                    if (--kv_handle_structs[current_ctx_ind].ctx->routs <= 10) {  // Check if it needs to post more receives
                        kv_handle_structs[current_ctx_ind].ctx->buf =
                                kv_handle_structs[current_ctx_ind].default_recv_buf.value;
                        kv_handle_structs[current_ctx_ind].ctx->mr =
                                kv_handle_structs[current_ctx_ind].default_recv_buf.mr;
                        kv_handle_structs[current_ctx_ind].ctx->size =
                                kv_handle_structs[current_ctx_ind].default_recv_buf.size;

                        kv_handle_structs[current_ctx_ind].ctx->routs += pp_post_recv(
                                kv_handle_structs[current_ctx_ind].ctx,
                                kv_handle_structs[current_ctx_ind].ctx->rx_depth - kv_handle_structs[current_ctx_ind].ctx->routs);

                        if (kv_handle_structs[current_ctx_ind].ctx->routs < kv_handle_structs[current_ctx_ind].ctx->rx_depth) {
                            fprintf(stderr, "Couldn't post receive (%d)\n", kv_handle_structs[current_ctx_ind].ctx->routs);
                            return 1;  // Return on failure to post receive
                        }
                    }

                    // Split between Server and Client for received messages
                    if (request != NULL) {
                        // TODO problematic, get function has other operation
                        strcpy(request, (char *) kv_handle_structs[current_ctx_ind].default_recv_buf.value);
                    }

                    // TODO combine these two if possibilities to one function

                    // Client side
                    if (servername) {
                        breakup_string_msg_client(
                                (char *)kv_handle_structs[current_ctx_ind].default_recv_buf.value,
                                &kv_handle_structs[current_ctx_ind], value);
                    }
                    // Server side
                    else {
                        breakup_string_msg_server(
                                (char *) kv_handle_structs[current_ctx_ind].default_recv_buf.value,
                                &kv_handle_structs[current_ctx_ind]);
                    }

                    break;

                // Representing the RDMA Write on a remote location, send ACK when done
                case PINGPONG_RDMA_OP:
                    ++srdmacnt;  // Increment RDMA send completion count/

                    if (PRINT_MSGS) {
                        printf("Performing RDMA Write to ");
                        if (servername) {
                            printf("Server\n");
                        }
                        else {
                            printf("Client: %d \n", current_ctx_ind);
                        }
                    }

                    break;

                default:
                    fprintf(stderr, "Completion for unknown wr_id %d\n", (int) wc[i].wr_id);
                    return 1;  // Return on unknown WR ID
            }
        }
    }
    return 0;  // Successful completion
}


int kv_set(void *kv_handle, const char *key, const char *value) {
    if (kv_handle == NULL || key == NULL || value == NULL)
        return 1;

    // Setting the key and value on the Client side
    size_t value_len = strlen(value)+1;

    // For the sake of brevity, we assume that a full SET request, along with the key and the value
    // Can be held in a 4KB request. TECHNICALLY a key is below 4KB, but what if it's 4095 bytes, along with a
    // value of 1 byte? the full SET request will be at around ~4100 bytes, let's assume simpler assumptions, thus:
    char request[MAX_KEY_SIZE];

    // Checking size of key + value and determining the type of message to be sent
    // Getting length of value, to be sent if large enough instead of value itself
    char value_len_str[20];              // Buffer to hold the string (20 bytes should be enough for a size_t)
    snprintf(value_len_str, sizeof(value_len_str), "%zu", value_len);

    size_t data_len = strlen(key) + strlen(value);
    // Two options from here:
    // 1. Regular Eager SET message, waiting for ACK
    // 2. RDMA Rendezvous SET message, waiting for MR to send information to,
    //                                                                  and send another ACK to the server at the end
    if (data_len > MAX_KEY_SIZE) {
        // TODO do we assume that kv_store has the correct key and value for the RENDEZVOUS situation here?
        //  I will check this, but maybe we should delete this part?
        struct node_pairs* cur_node = find_pairs(key, kv_store);
        if (cur_node == NULL) {
            return 1;
        }
        else {
            if (cur_node->pair == NULL) {
                return 1;
            }
            if (cur_node->pair->value != value) {
                printf("Given key-value pair is not the same one in the kv_store\n");
                return 1;
            }
        }

        // Sending RDMA MR creation request, need to wait for it to return the appropriate MR
        snprintf(request, sizeof(request), "%s %s %s", RDMA_SET_MSG, key, value_len_str);
        if (send_msg(kv_handle, request, (int) strlen(request) + 1)) {
            printf("Failed to send message: %s\n", request);
            return 1;
        }

        // Waiting for message to be sent AND for MR to be returned from server
        if(pp_wait_completions_split(kv_handle, 3, "Client", request, NULL, 1)) {
            return 1;
        }
    }
    else {
        // TODO for RDMA above we dont do set here, so why for EAGER? jsut make sure the kvstore is ready
        //  with pair from beforehand
        // For the eager, small case, we can simply copy the value to the kv_store
        /*struct node_pairs* cur_node = set_value_by_key(kv_handle, key, value);
        if (cur_node == NULL) {
            return 1;
        }*/

        snprintf(request, sizeof(request), "%s %s %s", SET_MSG, key, value);
        if (send_msg(kv_handle, request, (int) strlen(request) + 1)) {
            printf("Failed to send message: %s\n", request);
            return 1;
        }

        // Waiting for message to be sent
        if (pp_wait_completions_split(kv_handle, 1, "Client", request, NULL, 1)) {
            return 1;
        }
    }

    // Waiting for the ACK for SET operation
    if (pp_wait_completions_split(kv_handle, 1, "Client", NULL, NULL, 1)) {
        return 1;
    }

    return 0; // Success
}


// Performs a GET operation
// Client stops all other operations until the GET operation is fully complete,
// I.E. the value is returned from the Server to the Client and fills the **value with it
int kv_get(void *kv_handle, const char *key, char **value) {
    if (kv_handle == NULL || key == NULL || value == NULL || *value == NULL)
        return 1;

    // Sending the base GET request, which is always smaller/equal to 4096 bytes

    // For the sake of brevity, we assume that a full SET request, along with the key and the value
    // Can be held in a 4KB request. TECHNICALLY a key is below 4KB, but what if it's 4095 bytes, along with a
    // value of 1 byte? the full SET request will be at around ~4100 bytes, let's assume simpler assumptions, thus:
    char request[MAX_KEY_SIZE];

    snprintf(request, sizeof(request), "%s %s", GET_MSG, key);
    if (send_msg(kv_handle, request, (int) strlen(request) + 1)) {
        return 1;
    }

    char* get_ret_msg = malloc(MAX_KEY_SIZE * sizeof(char));
    if (get_ret_msg == NULL) {
        return 1;
    }

    // Waiting for the post send and recv to be completed
    if (pp_wait_completions_split(kv_handle, 2, "Client", get_ret_msg, value,
                                  1)) {
        return 1;
    }

    char* first_word = malloc(20 * sizeof(char));
    if (first_word == NULL) {
        return 1;
    }
    get_first_word(get_ret_msg, first_word);

    // From here, there are two options:
    // 1. Either the value on the server is too big(>4096 bytes)
    // 2. The value is small enough for a regular request (<4096 bytes)

    if (strcmp(first_word, GET_ACK_MSG) == 0) {
        if ((int) strlen(*value) == 0) {
            printf("The gotten value for key %s is empty\n", key);
            free(first_word);
            return 0;
        }
        if (PRINT_MSGS) {
            printf("GET request Value: %.30s\n", *value);
        }

        Node_pairs* cur_node = set_value_by_key(kv_handle, key, *value);
        if (!cur_node) {
            printf("Could not create a kv_store entry for a kv_set operation\n");
            return 1;
        }
    }
    else if(strcmp(first_word, RDMA_READ_MR_MSG) == 0) {
        // Waiting for the confirmation of sending the MR to server
        if (pp_wait_completions_split(kv_handle, 1, "Client", get_ret_msg, value,
                                      1)) {
            return 1;
        }

        // Waiting for ACK from server at end of the RDMA Write operation
        if (pp_wait_completions_split(kv_handle, 1, "Client", NULL, NULL,
                                      1)) {
            return 1;
        }

    }
    else {
        printf("Returned message for Get request not valid!\n");
        return 1;
    }

//    *value = MR_pair->value; // TODO

    free(get_ret_msg);
    free(first_word);

    return 0; // Success
}

// Releases the memory associated with a certain value in a key-value pair
void kv_release(char *value) {
    if (value == NULL)
        return;

    free(value); // Free the memory allocated for the value
}

// Helper function for kv_close which waits for all outstanding work requests to
// successfully to continue the closing operations
int wait_for_completions_for_closing(struct pingpong_context *ctx) {
    struct ibv_wc wc;
    int ret;

    while ((ret = ibv_poll_cq(ctx->cq, 1, &wc)) > 0) {
        if (wc.status != IBV_WC_SUCCESS) {
            fprintf(stderr, "Completion with error: %d\n", wc.status);
            return 1;
        }
    }
    if (ret < 0) {
        fprintf(stderr, "Polling CQ failed\n");
        return 1;
    }

    return 0; // All completions handled successfully
}


// Closes the Client, releasing the allocated memory
// TODO wait for all complete queue and THEN close
int kv_close(void *kv_handle) {
    struct kv_handle *kv_handle_struct = (struct kv_handle *) kv_handle;

    if(wait_for_completions_for_closing(kv_handle_struct->ctx)) {
        printf("Couldn't properly wait for CQ to finish to close the Client\n");
        return 1;
    }

    // Destroying empty pair
    if (empty_pair.value != NULL) {
        free(empty_pair.value);
    }
    if (empty_pair.mr != NULL) {
        ibv_dereg_mr(empty_pair.mr);
    }

    // Releasing all pairs of MR and malloced values of the KV store
    destroy_pairs(kv_store, true);

    // Destroying the default send buffer
    MR_pair_factory(kv_handle, &kv_handle_struct->default_send_buf, -1); // TODO replace with another func

    // Destroying the default receive buffer as part of the destruction process of the whole ctx
    kv_handle_struct->ctx->buf = kv_handle_struct->default_recv_buf.value;
    kv_handle_struct->ctx->mr = kv_handle_struct->default_recv_buf.mr;

    // Freeing the default buffer and corresponding Memory Region -- pp_close_ctx deals with it for us
    // Clean up RDMA context
    if (pp_close_ctx(kv_handle_struct->ctx)) {
        printf("Failed to properly close CTX\n");
        return 1;
    }
    free(kv_handle_struct);

    return 0; // Success
}

// The following code is used to process a txt file input to the C program we made
#define MAX_LINE_LENGTH 1024

// All possible commands that can be used by a Client
#define GET_COMMAND "get"
#define SET_COMMAND "set"
#define SET_BY_SIZE_COMMAND "setsize"
#define PRINT_KV_COMMAND "printkv"
#define WARMUP_COMMAND "warmup"

// Used to send useful helper control messages which are not part of the main operation of the system or the API
int send_extra_control_msg(void* kv_handle, char* msg_type) {
    struct kv_handle* kv_handle_struct = (struct kv_handle*) kv_handle;

    char request[MAX_KEY_SIZE];
    char request_extra[MAX_KEY_SIZE] = "";

    if (strcmp(msg_type, WARMUP_MSG) == 0) {
        generate_random_string(request_extra, 3000);
    }

    snprintf(request, sizeof(request), "%s %s", msg_type, request_extra);
    if (send_msg(kv_handle_struct, request, (int) strlen(request) + 1)) {
        printf("Failed to send message: %s\n", request);
        return 1;
    }

    // Waiting for message to be sent
    if (pp_wait_completions_split(kv_handle, 1, "Client", request, NULL, 1)) {
        return 1;
    }

    return 0;
}

// Processes a single sentence and performs the command given in it accordingly
// The possible commands are:
// set "key" "value"
// get "key"
// setsize "key" "value size"
// printkv
// warmup
int process_sentence(char *sentence, void* kv_handle) {
    // Example: Print the sentence (you can replace this with your processing logic)
    if (strlen(sentence) > 0) {
        char* token = strtok(sentence, " \n");
        if (token == NULL) {
            return 1;
        }

        if (strcmp(token, GET_COMMAND) == 0) {
            char* key = strtok(NULL, " \n");
            if (key == NULL) {
                return 1;
            }

            char* value = malloc(MAX_KEY_SIZE * sizeof(char));
            if (value == NULL) {
                return 1;
            }
            if (kv_get(kv_handle, key, &value)) {
                printf("kv GET operation failed\n");
                return 1;
            }
        }
        else if (strcmp(token, SET_COMMAND) == 0) {
            char* key = strtok(NULL, " \n");
            char* value = strtok(NULL, " \n");
            if (!(key && value)) {
                return 1;
            }

            // Adding the random value and the key to the CLIENT kv_store
            Node_pairs* cur_node = set_value_by_key(kv_handle, key, value);
            if (cur_node == NULL) {
                return 1;
            }

            if(kv_set(kv_handle, key, cur_node->pair->value)) {
                printf("kv SET operation failed\n");
                return 1;
            }
        }
        else if (strcmp(token, SET_BY_SIZE_COMMAND) == 0) {
            char* key = strtok(NULL, " \n");
            char* value_size = strtok(NULL, " \n");
            if (!(key && value_size)) {
                return 1;
            }

            uint32_t value_size_int = get_str_uint32_t(value_size);

            struct MR_place_pair* cur_pair = create_MR_place_pair_by_size(kv_handle, (int) value_size_int);
            if (cur_pair == NULL) {
                // TODO free others
                return 1;
            }
            generate_random_string(cur_pair->value, value_size_int);

            // Adding the random value and the key to the CLIENT kv_store
            Node_pairs* cur_node = set_MR_pair_by_key(kv_handle, key, cur_pair);
            if (cur_node == NULL) {
                // TODO free others
                return 1;
            }

            if(kv_set(kv_handle, key, cur_node->pair->value)) {
                printf("kv SET operation failed\n");
                return 1;
            }
        }
        else if (strcmp(token, PRINT_KV_COMMAND) == 0) {
            print_kv_store(kv_handle);

            send_extra_control_msg(kv_handle, PRINT_KV_MSG);
        }
        else if (strcmp(token, WARMUP_COMMAND) == 0) {
            send_extra_control_msg(kv_handle, WARMUP_MSG);
        }
        else {
            printf("Invalid sentence input\n");
        }
    }

    return 0;
}

// Processes a .txt file line-by-line
int process_txt_file(char* file_name, void* kv_handle) {
    if (file_name == NULL) {
        return 1;
    }

    FILE *file = fopen(file_name, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char line[MAX_LINE_LENGTH];

    // Read the file line by line
    while (fgets(line, sizeof(line), file)) {
        line[strlen(line)-1] = '\0';
        if(process_sentence(line, kv_handle)) {
            break;
        }
    }

    if (fclose(file) == EOF) {
        printf("Failed to close file\n");
        return 1;
    }

    return 0;
}

// This is part of our Exercise 2 code:
double calculate_throughput(struct timeval start_time, struct timeval end_time, int data_size_bytes, int iters) {
    int MEGABYTE = (1024 * 1024)/8;
    int MICROSECS_IN_SEC = 1000000;

    // Convert seconds and microseconds to total elapsed time in seconds
    double elapsed_time_in_seconds = (double)(end_time.tv_sec - start_time.tv_sec) +
            (double)(end_time.tv_usec - start_time.tv_usec) / MICROSECS_IN_SEC; // Time in seconds
    // Total data sent in Megabytes
    double total_data_megabytes = ((double)data_size_bytes * (double)iters) / MEGABYTE;

    // Throughput: total_data_sent / time_to_send_data
    return total_data_megabytes / elapsed_time_in_seconds;
}


// --------------------------------------- Main functions for Clients/Server ----------------------------------------

// Performs a throughput test by sending iters SET and GET requests of size key_size + value_size and
// calculating the data transfer rate of the system
int kv_throughput_test(void *kv_handle, int key_size, int value_size, int iters) {
    int bytes_to_send = key_size + value_size;

    // Creating random key and value to send with the test
    char* random_key = malloc(key_size * sizeof(char));
    if (random_key == NULL) {
        return 1;
    }
    char* random_value = malloc(value_size * sizeof(char));
    if (random_value == NULL) {
        free(random_key);
        return 1;
    }

    generate_random_string(random_key, key_size);
    generate_random_string(random_value, value_size);

    // Performing a single test SET operation
    if (kv_set(kv_handle, random_key, random_value)) {
        printf("kv SET operation failed\n");
        return 1;
    }

    struct timeval start_t;
    struct timeval end_t;

    // Performing WARMUP sends
    for (int i = 0; i < iters; i++) {
        send_extra_control_msg(kv_handle, WARMUP_MSG);
    }

    // Part 1: kv_set throughput
    printf("Performing SET operation throughput test\n"
           "We will send %d KV pairs of size: %d + %d bytes each\n", iters, value_size, key_size);
    gettimeofday(&start_t, NULL);

    for (int i = 0; i < iters; i++) {
        if(kv_set(kv_handle, random_key, random_value)) {
            printf("kv SET operation failed\n");
            return 1;
        }
    }

    gettimeofday(&end_t, NULL);
    printf("%-10d %-10.2f Mb/s\n", bytes_to_send, calculate_throughput(start_t, end_t,
                                                                       bytes_to_send, iters));

    // Part 2: kv_get throughput
    printf("Performing GET operation throughput test\n"
           "We will send %d keys of size: %d bytes each\n"
           "And receive values of size %d each\n", iters, key_size, value_size);

    gettimeofday(&start_t, NULL);

    for (int i = 0; i < iters; i++) {
        if (kv_get(kv_handle, random_key, &random_value)) {
            printf("kv GET operation failed\n");
            return 1;
        }
    }

    gettimeofday(&end_t, NULL);
    printf("%-10d %-10.2f Mb/s\n", bytes_to_send, calculate_throughput(start_t, end_t,
                                                                       bytes_to_send, iters));

    free(random_key); // TODO delete???????????

    return 0;
}

// Client input type wherein the Client performs throughput tests
int kv_client_throughput_test(void *kv_handle) {
    printf("\nPerforming EAGER throughput test with 1000 Byte sized values\n");
    if (kv_throughput_test(kv_handle, 2000, 1000, 1000)) {
        return 1;
    }

    printf("\nPerforming RENDEZVOUS throughput test with 1KB sized values\n");
    if (kv_throughput_test(kv_handle, 2000, 1024*1024, 1000)) {
        return 1;
    }

    return 0;
}

// Client input type wherein the Client inputs a file and processes it sentence-by-sentence
int kv_client_file_input(void *kv_handle) {
    char sentence[MAX_KEY_SIZE];
    printf("Enter your file's name: ");
    scanf("%s", sentence);  // Read a single word string
    process_txt_file(sentence, kv_handle);

    return 0;
}

// Client input type wherein the Client inputs a single command each time and processes it
int kv_client_text_input(void *kv_handle) {
    char sentence[MAX_KEY_SIZE];

    while (true) {
        fgets(sentence, sizeof(sentence), stdin);
        if (process_sentence(sentence, kv_handle)) {
            break;
        }
    }

    return 0;
}

// Client main function
int  kv_client_main(void *kv_handle) {
    // Deciding which type of client action will be taken
    printf("Please choose between the different client actions:\n"
           "throughput - testing the throughput of the system\n"
           "file - inputting a name of a txt file that describes the actions the client should take\n"
           "text - continuous single sentence text input\n");

    char sentence[MAX_LINE_LENGTH];
    // Go back here if you give the incorrect input type
    baseInput:
    fgets(sentence, sizeof(sentence), stdin);

    char* token = strtok(sentence, " \n");
    if (token == NULL) {
        return -1;
    }

    if (strcmp(token, "throughput") == 0) {
//        PRINT_MSGS = false;
        kv_client_throughput_test(kv_handle);
    }
    else if(strcmp(token, "file") == 0) {
//        PRINT_MSGS = true;
        kv_client_file_input(kv_handle);
    }
    else if(strcmp(token, "text") == 0) {
//        PRINT_MSGS = true;
        kv_client_text_input(kv_handle);
    }
    else {
        printf("Please enter the one of the correct input types\n");
        goto baseInput;
    }

    printf("---------- Finished Client run, closing kv_handle ----------\n");

    if (kv_close(kv_handle)) {
        printf("Failed to close the kv_handle");
        return 1;
    }

    return 0;
}

// Server main function
int kv_server_main(void *kv_handle, int num_of_connections) {
    sleep(5); // TODO wait for clients to send after connection

    bool dont_stop_server = true;

    // TODO while loop that is only broken with CLOSE msg?
    while (dont_stop_server) {
        if (pp_wait_completions_split(kv_handle, 1, NULL, NULL, NULL, num_of_connections)) {
            return 1;
        }
    }

    return 0;
}


// ------------------- Defining Multi Client to one server model, functions and helper structs --------------------

struct ctx_pair {
    struct pingpong_context* ctx;
    struct pingpong_dest* rem_dest;
};

// Multi client connection function
int connect_client(struct pingpong_context* ctx, int use_event, int ib_port, struct pingpong_dest my_dest,
        struct pingpong_dest *rem_dest, int gidx, char* gid, char* servername, enum ibv_mtu mtu, int port, int sl)  {
    if (ctx == NULL) {
        return 1;
    }

    // Post receive work requests
    ctx->routs = pp_post_recv(ctx, ctx->rx_depth);
    if (ctx->routs < ctx->rx_depth) {
        fprintf(stderr, "Couldn't post receive (%d)\n", ctx->routs); // Error handling
        return 1;
    }

    // Request notification for completion queue if using events
    if (use_event)
        if (ibv_req_notify_cq(ctx->cq, 0)) {
            fprintf(stderr, "Couldn't request CQ notification\n"); // Error handling
            return 1;
        }

    // Get port information for the specified IB port
    if (pp_get_port_info(ctx->context, ib_port, &ctx->portinfo)) {
        fprintf(stderr, "Couldn't get port info\n"); // Error handling
        return 1;
    }

    // Set local connection parameters
    my_dest.lid = ctx->portinfo.lid; // Local Identifier
    if (ctx->portinfo.link_layer == IBV_LINK_LAYER_INFINIBAND && !my_dest.lid) {
        fprintf(stderr, "Couldn't get local LID\n"); // Error handling
        return 1;
    }

    // Query the GID if an index is provided
    if (gidx >= 0) {
        if (ibv_query_gid(ctx->context, ib_port, gidx, &my_dest.gid)) {
            fprintf(stderr, "Could not get local gid for gid index %d\n", gidx); // Error handling
            return 1;
        }
    } else
        memset(&my_dest.gid, 0, sizeof my_dest.gid); // Clear GID if not used

    // Set additional connection parameters
    my_dest.qpn = ctx->qp->qp_num; // Queue Pair Number
    my_dest.psn = lrand48() & 0xffffff; // Packet Sequence Number
    inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid); // Convert GID to string
    printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
           my_dest.lid, my_dest.qpn, my_dest.psn, gid); // Print local connection info

    // ------------------------------ Server and Client code starts to differentiate from here ---------------------

    // Exchange connection parameters with the remote peer
    if (servername)
        rem_dest = pp_client_exch_dest(servername, port, &my_dest); // Client case
    else
        rem_dest = pp_server_exch_dest(ctx, ib_port, mtu, port, sl, &my_dest, gidx); // Server case

    if (!rem_dest) // Check for errors during exchange
        return 1;

    inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof gid); // Convert remote GID to string
    printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
           rem_dest->lid, rem_dest->qpn, rem_dest->psn, gid); // Print remote connection info

    // Connect to the remote peer if acting as a client
    if (servername)
        if (pp_connect_ctx(ctx, ib_port, my_dest.psn, mtu, sl, rem_dest, gidx))
            return 1;

    return 0;
}

// Starts a connection between a Client and the Server
int kv_open(char *servername, void **kv_handle) {
    // Unpacks the big pseudo-struct that was given in the name of kv_handle,
    // Although it is not the same type of kv_handle as the rest of the program
    struct ctx_pair* ctx_pairs = kv_handle[0];
    struct ibv_device       *ib_dev=kv_handle[1];
    int                      size=*(int *)(kv_handle[2]);
    int                      rx_depth =*(int *)(kv_handle[3]);
    int                      tx_depth =*(int *)(kv_handle[4]);
    int                      ib_port= *(int *)(kv_handle[5]);
    int                      use_event = *(int *)(kv_handle[6]);
    struct pingpong_dest     *my_dest=(kv_handle[7]);
    int                      port =*(int *)(kv_handle[8]);
    int                      sl =*(int *)(kv_handle[9]);
    int                      gidx =*(int *)(kv_handle[10]);
    char                     *gid=(char *)(kv_handle[11]);

    // Initialize the RDMA context
    ctx_pairs->ctx = pp_init_ctx(ib_dev, size, rx_depth, tx_depth, ib_port, use_event, !servername);
    if (!ctx_pairs->ctx) // Check for initialization errors
        return 1;

    connect_client(ctx_pairs->ctx, use_event, ib_port, *my_dest, ctx_pairs->rem_dest, gidx, gid, servername,
                   IBV_MTU_2048, port, sl);

    return 0; // Success
}


int main(int argc, char *argv[])
{
    // Declare variables for RDMA device management and context
    struct ibv_device      **dev_list;        // List of available IB devices
    struct ibv_device       *ib_dev;          // Selected IB device

    struct ctx_pair* ctx_pairs; // TODO Jonathan added this

    struct pingpong_dest     my_dest;         // Local connection parameters
    char                    *ib_devname = NULL; // Device name from command-line
    char                    *servername;      // Server name for connection
    int                      port = 20360;    // Port number for communication // 12345
    int                      ib_port = 1;     // IB port number to use
    enum ibv_mtu             mtu = IBV_MTU_2048; // Maximum Transmission Unit
    int                      rx_depth = 100;  // Depth of receive queue
    int                      tx_depth = 100;  // Depth of send queue
    int                      iters = 1;    // Number of iterations for send/recv  // Originally 1000
    int                      use_event = 0;    // Flag for event-driven mode
    int                      size = 4096;        // Size of the messages to send // Originally 1
    int                      sl = 0;          // Service Level for QoS
    int                      gidx = -1;       // GID index for multicast
    char                     gid[33];         // Buffer for Global Identifier

    srand48(getpid() * time(NULL)); // Seed random number generator for PSN

    // Parse command-line options
    while (1) {
        int c;

        // Define long options for command-line arguments
        static struct option long_options[] = {
                { .name = "port",     .has_arg = 1, .val = 'p' },
                { .name = "ib-dev",   .has_arg = 1, .val = 'd' },
                { .name = "ib-port",  .has_arg = 1, .val = 'i' },
                { .name = "size",     .has_arg = 1, .val = 's' },
                { .name = "mtu",      .has_arg = 1, .val = 'm' },
                { .name = "rx-depth", .has_arg = 1, .val = 'r' },
                { .name = "iters",    .has_arg = 1, .val = 'n' },
                { .name = "sl",       .has_arg = 1, .val = 'l' },
                { .name = "events",   .has_arg = 0, .val = 'e' },
                { .name = "gid-idx",  .has_arg = 1, .val = 'g' },
                { 0 } // End of options
        };

        // Get the next command-line option
        c = getopt_long(argc, argv, "p:d:i:s:m:r:n:l:eg:", long_options, NULL);
        if (c == -1) // Break the loop if no more options
            break;

        switch (c) {
            // Handle command-line options
            case 'p':
                port = strtol(optarg, NULL, 0); // Set port number
                if (port < 0 || port > 65535) { // Validate port range
                    usage(argv[0]); // Show usage information
                    return 1;
                }
                break;

            case 'd':
                ib_devname = strdup(optarg); // Store IB device name
                break;

            case 'i':
                ib_port = strtol(optarg, NULL, 0); // Set IB port number
                if (ib_port < 0) { // Validate IB port number
                    usage(argv[0]); // Show usage information
                    return 1;
                }
                break;

            case 's':
                size = strtol(optarg, NULL, 0); // Set message size
                break;

            case 'm':
                mtu = pp_mtu_to_enum(strtol(optarg, NULL, 0)); // Set MTU
                if (mtu < 0) {
                    usage(argv[0]); // Show usage information
                    return 1;
                }
                break;

            case 'r':
                rx_depth = strtol(optarg, NULL, 0); // Set receive queue depth
                break;

            case 'n':
                iters = strtol(optarg, NULL, 0); // Set number of iterations
                break;

            case 'l':
                sl = strtol(optarg, NULL, 0); // Set service level
                break;

            case 'e':
                ++use_event; // Enable event-driven mode
                break;

            case 'g':
                gidx = strtol(optarg, NULL, 0); // Set GID index
                break;

            default:
                usage(argv[0]); // Show usage information for invalid option
                return 1;
        }
    }

    // Check for server name in command-line arguments
    if (optind == argc - 1)
        servername = strdup(argv[optind]); // Set server name from argument
    else if (optind < argc) {
        usage(argv[0]); // Show usage information for invalid arguments
        return 1;
    }

    page_size = sysconf(_SC_PAGESIZE); // Get the system's page size

    // Get the list of available IB devices
    dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        perror("Failed to get IB devices list"); // Error handling
        return 1;
    }

    // Select the IB device to use
    if (!ib_devname) {
        ib_dev = *dev_list; // Select the first device if none specified
        if (!ib_dev) {
            fprintf(stderr, "No IB devices found\n"); // Error handling
            return 1;
        }
    } else {
        int i;
        // Search for the specified IB device in the list
        for (i = 0; dev_list[i]; ++i)
            if (!strcmp(ibv_get_device_name(dev_list[i]), ib_devname))
                break;
        ib_dev = dev_list[i]; // Assign the found device
        if (!ib_dev) {
            fprintf(stderr, "IB device %s not found\n", ib_devname); // Error handling
            return 1;
        }
    }

    // OUR CODE STARTS FROM HERE -------------------------------------------------------------------------------
    // Initializing static variables
    init_kv_store();

    // Packaging the required parameters for kv_open
    void **data = (void **) malloc(sizeof(void *) * 12);
    if (data == NULL) {
        return 1;
    }
    ctx_pairs = malloc(sizeof(struct ctx_pair));
    if (ctx_pairs == NULL) {
        free(data);
        return 1;
    }
    data[0]=ctx_pairs;
    data[1]=ib_dev;
    data[2]=&size;
    data[3]=&rx_depth;
    data[4]=&tx_depth;
    data[5]=&ib_port;
    data[6]=&use_event;
    data[7]=&my_dest;
    data[8]=&port;
    data[9]=&sl;
    data[10]=&gidx;
    data[11]=gid;

    if (servername) {
        kv_open(servername,data);
    }
    // Connecting to each Client on the Server, the Server awaits until N_CLIENTS have connected
    else {
        ctx_pairs = malloc(N_CLIENTS * sizeof(struct ctx_pair));
        if (ctx_pairs == NULL) {
            // TODO free other mallocs
            return 1;
        }

        for (int i = 0; i < N_CLIENTS; i++) {
            // Initialize the RDMA context
            ctx_pairs[i].ctx = pp_init_ctx(ib_dev, size, rx_depth, tx_depth, ib_port, use_event,
                                           !servername);
            if (!ctx_pairs[i].ctx) // Check for initialization errors
                return 1;

            connect_client(ctx_pairs[i].ctx, use_event, ib_port, my_dest, ctx_pairs[i].rem_dest, gidx, gid,
                           servername, mtu, port, sl);
        }
    }

    // Both the server and the clients should have a kv_handle which holds the relevant context and the KV pairs

    // Generating Random Seed -------------------------------------------- START
    void* rand_place = malloc(1);
    if (rand_place == NULL) {
        return 1;
    }

    time_t cur_time = time(NULL);
    srand(cur_time + (time_t) rand_place);

    free(rand_place);
    // Generating Random Seed -------------------------------------------- END

    // Client Code
    if (servername) {
        struct kv_handle *kv_handle_struct = malloc(sizeof(struct kv_handle));
        if (kv_handle_struct == NULL) {
            // TODO free others
            return 1;
        }
        kv_handle_struct->ctx = ctx_pairs->ctx;

        if (init_empty_pair(kv_handle_struct)) {
            return 1;
        }

        // Default receive buffer is going to take the previous default ctx buffer as it was made
        //  in the original program
        kv_handle_struct->default_recv_buf.value = kv_handle_struct->ctx->buf;
        kv_handle_struct->default_recv_buf.mr = kv_handle_struct->ctx->mr;
        kv_handle_struct->default_recv_buf.size = MAX_KEY_SIZE;

        // Initializing default send buf
        kv_handle_struct->default_send_buf.value = NULL;
        kv_handle_struct->default_send_buf.mr = NULL;
        kv_handle_struct->default_send_buf.size = 0;

        // Default sending buffer will be created along-side it
        if(MR_pair_factory(kv_handle_struct, &(kv_handle_struct->default_send_buf), // TODO replace with another func
                           MAX_KEY_SIZE)) {
            return 1;
        }

        kv_client_main(kv_handle_struct);
    }
    // Server Code
    else {
        struct kv_handle *kv_handle_structs = malloc(N_CLIENTS * sizeof(struct kv_handle));
        if (kv_handle_structs == NULL) {
            // TODO free others
            return 1;
        }

        for (int i = 0; i < N_CLIENTS; i++) {
            kv_handle_structs[i].ctx = ctx_pairs[i].ctx;

            // Default receive buffer is going to take the previous default ctx buffer as it was made
            //  in the original program
            kv_handle_structs[i].default_recv_buf.value = kv_handle_structs[i].ctx->buf;
            kv_handle_structs[i].default_recv_buf.mr = kv_handle_structs[i].ctx->mr;
            kv_handle_structs[i].default_recv_buf.size = MAX_KEY_SIZE;

            // Initializing default send buf
            kv_handle_structs[i].default_send_buf.value = NULL;
            kv_handle_structs[i].default_send_buf.mr = NULL;
            kv_handle_structs[i].default_send_buf.size = 0;

            // Default sending buffer will be created along-side it
            if(MR_pair_factory(&(kv_handle_structs[i]), &(kv_handle_structs[i].default_send_buf), // TODO replace with another func
                               MAX_KEY_SIZE)) {
                return 1;
            }
        }

        if (init_empty_pair(&kv_handle_structs[0])) {
            return 1;
        }

        kv_server_main(kv_handle_structs, N_CLIENTS);
    }

    // Cleanup resources
    ibv_free_device_list(dev_list); // Free device list

    // Freeing the unrelated memory from main(), which is not directly related or given to kv_close
    if (servername) {
        free(ctx_pairs->rem_dest); // Free remote destination structure for Client
    }
    else {
        for(int i = 0; i < N_CLIENTS; i++) {
            free(ctx_pairs[i].rem_dest); // Free remote destinations structure for Server
        }
    }
    free(ctx_pairs);

    return 0; // Exit program successfully
}
