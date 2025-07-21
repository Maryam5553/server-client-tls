# Implementing a Certification Authority and TLS client-server protocol in C

## Presentation

This personal project is an implementation from scratch of a Public Key Infrastructure (PKI), using OpenSSL library. It features a custom Certification Authority, able to handle Certificate Signing Requests (CSR) and X.509 certificates; and a client-server communication implementing a TLS protocol and using mutual authentication.

It demonstrates an understanding of X.509 certificates generation, TLS chain of trust, CSR handling following PKCS#10 standard, and secure socket programming.

**Features**

1. A Certification Autority (CA):
    - generates a 2048-bits RSA private key;
    - generates a self-signed certificate in PEM format;
    - receives and verifies CSR;
    - signs CSR using its private key and self-signed certificate as a root certificate.

2. Client and server programs:
    - generate a private key;
    - generate a CSR and send it to CA;
    - establish a TCP connection with each other, accepting **only** certificates emitted using the trusted root certificate;
    - communicate in an TLS-encrypted channel, insuring confidentiality and integrity of the data.

## Prerequisites

This project was developped and tested in the following environment:
```
OS: Ubuntu 22.04.5
Compilation: gcc 11.4.0
Build tool: GNU Make 4.3
Library: OpenSSL 3.0.2 15 Mar 2022
```

CA default port is 8082, as defined in `CA/CA.c` and `tools/connect_to_CA.h`; and server default port is 8080, as defined in `server/server.h`.

## Demo
