# Usage

1. In root directory, execute `make`. This will compile the CA, server and client programs.

2. Open 3 terminals: one in CA/ `cd CA/`, one in server/ `cd server/`, one in client/ `cd client/`.

3. From the terminal CA/, launch the CA: `./CA`. The CA will start by generating its private files: a private key, and a self-signed certificate that will serve as a root certificate when generating user certificates. Then the CA will listen for incoming connexions.

4. While the CA program is still running: from the terminal server/, launch the server `./main`. The server will start by generating a private key. Then it will generate a Certificate Signing Request (CSR), signed with its private key. Then the server will connect to the CA and send the CSR. Upon receiving the CSR, the CA will check if the CSR is correctly signed. If it is, it will proceed by generating a TLS certificate using the information in the CSR, the CA certificate as a root certificate, and the CA private key to sign it. Then the CA will send first the root key and secondly the TLS certificate to the server. Finally, the server will write the two certificates in two files.

After receiving a TLS certificate, the server will be done initializing. Now the server will wait for incoming connexions by the client.

5. While the CA program is still running:  from the terminal client/, launch the client `./main`. The client will initialize the same way as the server. Once receiving its TLS certificate, it will then connect to the server and exchange data.