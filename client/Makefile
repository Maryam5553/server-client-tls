CC = gcc
CFLAGS = -Wall -g
SSLFLAGS = -lssl -lcrypto

TOOL_DIR = ../tools/

all: main

main: main.o client.o $(TOOL_DIR)ssl_err.o $(TOOL_DIR)init_peer.o $(TOOL_DIR)gen_credentials.o $(TOOL_DIR)file_exists.o $(TOOL_DIR)request_TLS_certificate.o $(TOOL_DIR)connect_to_CA.o $(TOOL_DIR)serialization.o
	$(CC) -o $@ $^ $(SSLFLAGS)

main.o: main.c client.h $(TOOL_DIR)init_peer.h
	$(CC) -c $^ $(SSLFLAGS)

#client functions
client.o: client.c client.h $(TOOL_DIR)ssl_err.h
	$(CC) -c $^ $(SSLFLAGS)

ssl_err.o: $(TOOL_DIR)ssl_err.c $(TOOL_DIR)ssl_err.h
	$(CC) -c $^ $(SSLFLAGS)

#certificate generating functions
init_peer.o: $(TOOL_DIR)init_peer.c $(TOOL_DIR)init_peer.h $(TOOL_DIR)gen_credentials.h $(TOOL_DIR)file_exists.h $(TOOL_DIR)request_TLS_certificate.h
	$(CC) -c $^ $(SSLFLAGS)

gen_credentials.o: $(TOOL_DIR)gen_credentials.c $(TOOL_DIR)gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

file_exists.o: $(TOOL_DIR)file_exists.c $(TOOL_DIR)file_exists.h
	$(CC) -c $^ $(SSLFLAGS)

request_TLS_certificate.o: $(TOOL_DIR)request_TLS_certificate.c $(TOOL_DIR)request_TLS_certificate.h $(TOOL_DIR)gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)
	
connect_to_CA.o: $(TOOL_DIR)connect_to_CA.c $(TOOL_DIR)connect_to_CA.h $(TOOL_DIR)serialization.h
	$(CC) -c $^ $(SSLFLAGS)

serialization.o: $(TOOL_DIR)serialization.c $(TOOL_DIR)serialization.h
	$(CC) -c $^ $(SSLFLAGS)

clean:
	rm -f *.o $(TOOL_DIR)*.o *.gch $(TOOL_DIR)*.gch main