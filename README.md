# Implementing a Certification Authority and TLS client-server communication in C

## Presentation

This personal project is an implementation from scratch of a simplified Public Key Infrastructure (PKI) using OpenSSL library. It features a custom Certification Authority, able to handle Certificate Signing Requests (CSR) and X.509 certificates; and a client-server communication protocol, secured with TLS and mutual authentication.

It demonstrates an understanding of X.509 certificates generation, TLS chain of trust, PKCS#10 CSR handling, and secure socket programming.

**Features:**

1. A Certification Authority (CA):
    - generates a 2048-bits RSA private key;
    - generates a self-signed certificate in PEM format;
    - receives and verifies CSR;
    - signs CSR using its private key and the self-signed certificate as a root certificate.

2. Client and server programs:
    - generate a private key;
    - generate a CSR and send it to CA;
    - accept communication with each other **only** if the other peer presents a certificate emitted with a trusted root certificate.
    - establish a TCP connection and communicate in an TLS-encrypted channel, insuring confidentiality and integrity of the exchanged data.

## Prerequisites

This project was developed and tested in the following environment:
```
OS: Ubuntu 22.04.5
Compilation: gcc 11.4.0
Build tool: GNU Make 4.3
Library: OpenSSL 3.0.2 15 Mar 2022
```

CA default port is 8080, as defined in `CA/CA.c` and `tools/connect_to_CA.h`; and server default port is 8081, as defined in `server/server.h` and `client/client.h`.

## Demo

### Step 1: Compilation

From the root directory, execute `make` to compile the CA, server, and client programs.

### Step 2: CA setup

Open a terminal in `CA/` subdirectory, and execute `./CA` to launch the Certification Authority program.

Expected result:

```console
CA$ ./CA
***** CERTIFICATION AUTHORITY SETUP *****
CA private key generated in file CA_key.pem.
CA generated self-signed certificate CA_cert.pem using private key CA_key.pem.
***** SETUP DONE *****

CA is listening on port 8080 for incoming connexions...
```
The CA will start by generating a private key, then a self-signed certificate.

All private keys are protected from being modified by anyone, and from being read by unauthorized users, by giving them strict read-only permissions.

```console
CA$ ls -l
-rw-rw-r-- CA_cert.pem
-r-------- CA_key.pem
```

The CA then listens for incoming CSR. Make sure this program is running when starting the server and the client.

### Step 3: server setup

Open a second terminal in the subdirectory `server/`. Execute `./main` to launch the server.

The server will generate a private key and check whether it already owns a TLS certificate. Because it's the first time we launch the server, it doesn't. So, the server will connect to the CA and request a TLS certificate. 

#### Details of the process on the server side

Here is the expected result from the previous step:

```console
server$ ./main
***** SERVER SETUP *****
server private key generated in file serv_key.pem.
No TLS certificate found: let's request a certificate to CA.
CSR generated using private key serv_key.pem.
Established connexion to CA at adress 127.0.0.1:8080
CSR sent to CA.
Waiting for CA to send root certificate...
Root certificate received.
Waiting for CA to send TLS certificate...
TLS certificate received.
TLS certificate and root certificate written in serv_cert.pem and CA_cert.pem.
Connexion with CA closed.
***** SETUP DONE *****
```

The protocol is as follows:
- the server generates a CSR and signs it with its private key;
- the server establishes a connexion with the CA and sends the CSR;
- the CA sends the root certificate;
- the CA sends the server's certificate.

When this setup is done, the server will have access to 2 certificates:

- The server's certificate will be the one presented to clients during a connection to authenticate the server.

- The root certificate will act as a trust anchor to verify other certificates. In particular, when a client tries to connect to the server, its certificate will be considered valid only if it was signed by the root certificate's key.

This ensures that both parties are part of the same chain of trust, rooted in the mutually trusted CA.

#### Details of the process on the CA side:

Here is how the CA issues a certificate (this is printed on the CA's side when the server is setting up):

```console
Client connected.
Waiting for CSR requests from connected client...
checked CSR: CSR signature is valid.
Client certificate generated.
Sending root certificate...
Root certificate sent.
Sending client certificate...
TLS certificate sent to client!
Done treating the CSR request.
```

The CA only emits a certificate if the CSR signature is valid.

#### Note: Security concerns.

>We can notice that the CA **doesn't proceed** with any **identity verification** of the requester. In fact, it will issue a certificate to anyone, as long as the CSR is well-formed. This is contrary to real life, where the CA will confirm **domain control** and organizational identity validation.
>
>This project doesn't cover this part as it is only an example of a simplified PKI, covering only the certificate generation protocol and the role of TLS certificates in communications between peers.
>
>Let's also note that the communication between CA and the requester isn't secure. In a real world scenario, this would compromise the integrity of the request and lead to possible Man-in-the-Middle scenarios. The security of this scheme would fall as it lies in the trust of the root certificate.

#### After the server setup

The previous steps were meant to generate a TLS certificate for the server. After this, the setup is complete. The server will wait for clients to connect.

```console
server$ ./main
***** SERVER SETUP *****
[...]
***** SETUP DONE *****

Server listening on port 8081...
```

### Step 4: client setup and communication with the server

Now that the server is set up, we'll do the same thing for the client.

#### Design choice for a mutual authentication
In a traditional server-client protocol (like HTTPS), only the client verifies the other party's authenticity. In this project, I wanted to emphasize the concept of a trust chain, where both parties must prove their identity through a common authority, which is at the heart of Public Key Infrastructure (PKI) systems. So here, the server will proceed to the same verification.

#### Setup
For this step, make sure the CA program is still running (this will serve for the client certificate request), and the server program is still running (so that the client can try to connect to the server).

Open a third terminal in the subdirectory `client/`. Execute `./main` to start the client.

You should get the same result as the server initialization:

```console
client$ ./main 
***** CLIENT *****
client private key generated in file client_key.pem.
No TLS certificate found: let's request a certificate to CA.
CSR generated using private key client_key.pem.
Established connexion to CA at address 127.0.0.1:8080
CSR sent to CA.
Waiting for CA to send root certificate...
Root certificate received.
Waiting for CA to send TLS certificate...
TLS certificate received.
TLS certificate and root certificate written in client_cert.pem and CA_cert.pem.
Connexion with CA closed.
***** SETUP DONE *****
```

#### TLS connection to the server

The setup is now completed. The server and client now have TLS certificates that they mutually recognize. The client will try to establish a connection with the server.

On the client side:

```console
client$ ./main
[...]
Connexion to the server at address 127.0.0.1:8081.
Initiating TLS handshake with the server
TLS handshake was successful. Client connected securely.
Wrote: "hello"
Read: "hello".
Sent close_notify to the server.
Shutdown completed.
```
On the server side:

```console
server$ ./main
[...]
Server listening on port 8081...
New client
Waiting for client to initiate TLS handshake...
TLS handshake completed. Client connected securely.
Client connected securely.
Read: "hello".
Wrote: "hello".
error reading data.
The peer has closed the connection for writing by sending the close_notify alert.Sent close_notify to the peer. Connexion successfully closed.
```
Here is the protocol:
- the client opens a TCP socket to connect to the server
- the client initiates the TLS handshake
- both parties present their X.509 certificate and verify the peer's certificate against the trusted root certificate issued by the CA. If they both verify the chain of trust, the authenticity of the other peer is confirmed, and the TLS handshake is completed.
- after this stage, all data exchanged between server and client is encrypted using symmetric keys derived from the TLS handshake. This ensures both confidentiality and integrity. The server and client can exchange data until one side closes the connection.

## Conclusion

We've demonstrated how secure communication between peers can be established through mutual authentication, and how Certification Authorities implement a trusted chain of trust. It highlights the key principles behind Public Key Infrastructures (PKI), and showcases a practical example of authenticated, encrypted communication.

## Future improvements

While this project serves as a good example of a basic Certification Authority, here are some improvements I would implement to solidify this scheme:

- introducing **intermediary certificates**, to better represent how certificates are chained and issued to a requester in real life;
- adding **Certificate Revocation Lists** (CRL) to revoke expired or compromised certificates, and enforce a real-time revocation check;
- securize communication between CA and requester, for example by requiring a pre-shared key;
- containerize the CA, client and server programs to simplify setup and deployment.