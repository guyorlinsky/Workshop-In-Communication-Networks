//////
////// Created by amittai.lerer on 6/5/24.


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define PORT 8081
#define BUFFER_SIZE 1048576 // 1MB

#define BIT_SIZE 8
#define MEGA_COEFFICIENT (1024 * 1024)
#define MSG_SIZE_INC 2
#define DEFAULT_SERVER_IP "132.65.164.101"
#define ITER_POS_BUFF 5
#define WARMUP_NUM 200

#define NUM_OF_MSG_SIZES 21

#define SOCKET_CREATION_ERROR "Socket creation error"

#define INVALID_ADRS_MSG "Invalid address/ Address not supported"

#define CONNECTION_FAILD_MSG "Connection Failed"

#define BUFFER_ALOC_FALIED_MSG "Buffer allocation error"

// Function to get the current time in seconds with high precision
double get_time_in_seconds() {
    struct timeval time;
    gettimeofday(&time, NULL);
    return time.tv_sec + time.tv_usec / 1000000.0;
}

// Function to create and configure the socket
int create_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror(SOCKET_CREATION_ERROR);
        exit(EXIT_FAILURE);
    }
    return sock;
}

// Function to export data to CSV file
void export_to_csv(double x[], double y[], int num_points) {
    // Open CSV file for writing
    FILE *fp = fopen("data.csv", "w");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    // Write headers
    fprintf(fp, "X,Y\n");

    // Write data
    for (int i = 0; i < num_points; ++i) {
        fprintf(fp, "%.1f,%.4f\n", x[i], y[i]);
    }

    // Close file
    fclose(fp);

    printf("Data exported to 'data.csv'\n");
}


// Function to set up server address structure
void setup_server_address(struct sockaddr_in *serv_addr, const char *server_ip) {
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, server_ip, &serv_addr->sin_addr) <= 0) {
        perror(INVALID_ADRS_MSG);
        exit(EXIT_FAILURE);
    }
}

// Function to connect to the server
void connect_to_server(int sock, struct sockaddr_in *serv_addr) {
    if (connect(sock, (struct sockaddr *)serv_addr, sizeof(*serv_addr)) < 0) {
        perror(CONNECTION_FAILD_MSG);
        close(sock);
        exit(EXIT_FAILURE);
    }
}

// Function to perform the warmup phase
void warmup(int sock, char *buffer, size_t size, int warmup_iterations) {
    for (int j = 0; j < warmup_iterations; ++j) {
        ssize_t bytes_written = write(sock, buffer, size);
        if (bytes_written < 0) {
            perror("write");
            close(sock);
            free(buffer);
            exit(EXIT_FAILURE);
        }
    }
}

void measure_throughput(int sock, char *buffer, size_t size, int iterations, double *size_arr, double *throughput_arr, int index) {
    size_t bytes_sent = 0;
    double start_time = get_time_in_seconds();

    for (int j = 0; j < iterations; ++j) {
        ssize_t bytes_written = write(sock, buffer, size);
        if (bytes_written < 0) {
            perror("write");
            close(sock);
            free(buffer);
            exit(EXIT_FAILURE);
        }
        bytes_sent += (size_t)bytes_written;
    }

    double end_time = get_time_in_seconds();
    double time_diff = end_time - start_time;
    double throughput = ((double)(bytes_sent * BIT_SIZE)) / (time_diff * MEGA_COEFFICIENT); // Mbps per unit packet size
    printf("%8zu    %11f    Mbps\n", size, throughput);

    // Save size and throughput to arrays
    size_arr[index] = (double)size;
    throughput_arr[index] = throughput;
}


int main(int argc, char *argv[]) {
    // Default server IP address to connect
    const char *server_ip = (argc == 2) ? argv[1] : DEFAULT_SERVER_IP;

    // Create and configure socket
    int sock = create_socket();

    // Setup server address
    struct sockaddr_in serv_addr;
    setup_server_address(&serv_addr, server_ip);

    // Connect to the server
    connect_to_server(sock, &serv_addr);

    // Allocate buffer
    char *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        perror(BUFFER_ALOC_FALIED_MSG);
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Arrays to store size and throughput
    double size_arr[NUM_OF_MSG_SIZES];
    double throughput_arr[NUM_OF_MSG_SIZES];


    // Print header
    printf("message    size    throughput  units\n");

    // Perform data transfer for various message sizes
    size_t size = 1;
    int iterations[] = {100000, 100000, 2500, 100, 80};

    // Explanation:
    // The `iterations` array specifies the number of times data is sent to the server
    // for different ranges of message sizes. This helps in efficiently measuring the
    // throughput for each message size, balancing the trade-off between measurement
    // accuracy and execution time.

    for (int i = 0; i < NUM_OF_MSG_SIZES; ++i) {
        memset(buffer, 'a', size);

        // Determine position in iteration and warmup arrays based on current index
        int pos = i / ITER_POS_BUFF;

        // Warmup phase
        warmup(sock, buffer, size, WARMUP_NUM);

        // Measure and print throughput
//        measure_throughput(sock, buffer, size, iterations[pos]);
        measure_throughput(sock, buffer, size, iterations[pos], size_arr, throughput_arr, i);

        // Increase message size for next iteration
        size *= MSG_SIZE_INC;
    }


    // Clean up: Close socket and free allocated memory
    close(sock);
    free(buffer);

    // Export data to CSV
    export_to_csv(size_arr, throughput_arr, NUM_OF_MSG_SIZES);

    return EXIT_SUCCESS;
}
