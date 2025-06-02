CC = gcc
CFLAGS = -Wall -g
SSLFLAGS = -lssl -lcrypto

all: test_credentials test_connect_to_CA

# Test file for gen_credentials
test_credentials: test_credentials.o gen_credentials.o
	$(CC) -o $@ $^ $(SSLFLAGS)

test_credentials.o: test_credentials.c gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

# gen_credentials
gen_credentials.o: gen_credentials.c gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

# Test file for connect_to_CA
test_connect_to_CA: test_connect_to_CA.o connect_to_CA.o serialization.o gen_credentials.o
	$(CC) -o $@ $^ $(SSLFLAGS)

test_connect_to_CA.o: test_connect_to_CA.c connect_to_CA.h serialization.h gen_credentials.h
	$(CC) -c $^ $(SSLFLAGS)

# connect_to_CA
connect_to_CA.o: connect_to_CA.c connect_to_CA.h
	$(CC) -c $^ $(SSLFLAGS)

# serialization
serialization.o: serialization.c serialization.h
	$(CC) -c $^ $(SSLFLAGS)

clean:
	rm -f *.o *.gch 
	rm -f test_connect_to_CA test_credentials
	rm -f *.pem