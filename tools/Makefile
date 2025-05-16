CC = gcc
CFLAGS = -Wall -g
SSLFLAGS = -lssl -lcrypto

all: test_credentials # to compile test file for gen_credentials

test_credentials: test_credentials.o $(TOOL_DIR)gen_credentials.o
	$(CC) -o $@ $^ $(SSLFLAGS)

test_credentials.o: test_credentials.c $(TOOL_DIR)gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

gen_credentials.o: $(TOOL_DIR)gen_credentials.c $(TOOL_DIR)gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

clean:
	rm -f *.o $(TOOL_DIR)*.o *.gch $(TOOL_DIR)*.gch server
	rm test_key.pem test_cert.pem