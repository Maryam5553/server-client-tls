.PHONY: all CA client server clean

all: CA client server

# compile CA program
CA:
	$(MAKE) -C CA

# compile client program
client:
	$(MAKE) -C client

#compile server program
server:
	$(MAKE) -C server

clean:
	$(MAKE) -C CA clean
	$(MAKE) -C client clean
	$(MAKE) -C server clean
