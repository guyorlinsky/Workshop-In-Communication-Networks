# Makefile for compiling the client and server programs

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Targets
CLIENT = client
SERVER = server

# Source files
CLIENT_SRC = client.c
SERVER_SRC = server.c

# Default target to build both client and server
all: $(CLIENT) $(SERVER)

# Rule to build the client
$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT_SRC)

# Rule to build the server
$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $(SERVER) $(SERVER_SRC)

# Clean target to remove built files
clean:
	rm -f $(CLIENT) $(SERVER)

# Phony targets
.PHONY: all clean
