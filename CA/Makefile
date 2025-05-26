CC = gcc
CFLAGS = -Wall -g
SSLFLAGS = -lssl -lcrypto

TOOL_DIR = ../tools/

all: CA

CA: CA.o $(TOOL_DIR)file_exists.o $(TOOL_DIR)gen_credentials.o
	$(CC) -o $@ $^ $(SSLFLAGS)

CA.o: CA.c $(TOOL_DIR)file_exists.h $(TOOL_DIR)gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

file_exists.o: $(TOOL_DIR)file_exists.c $(TOOL_DIR)file_exists.h
	$(CC) -c $^ $(SSLFLAGS)

gen_credentials.o:$(TOOL_DIR)gen_credentials.c $(TOOL_DIR)gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

clean:
	rm -f *.o $(TOOL_DIR)*.o *.gch $(TOOL_DIR)*.gch CA