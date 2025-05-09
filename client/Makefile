CC = gcc
CFLAGS = -Wall -g
SSLFLAGS = -lssl -lcrypto

TOOL_DIR = ../tools/

all: client

client: client.o $(TOOL_DIR)ssl_err.o
	$(CC) -o $@ $^ $(SSLFLAGS)

client.o: client.c $(TOOL_DIR)ssl_err.h
	$(CC) -c $^ $(SSLFLAGS)

ssl_err.o: $(TOOL_DIR)ssl_err.c $(TOOL_DIR)ssl_err.h
	$(CC) -c $^ $(SSLFLAGS)

clean:
	rm -f *.o $(TOOL_DIR)*.o *.gch $(TOOL_DIR)*.gch client