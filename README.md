# Libcoap sample client

This is a CoAP client sample for Raspberry Pi/Linux with the [libcoap](https://libcoap.net) library. This 
sample uses the built-in transport layer included with the library.

This example builds on Linux/Raspberry Pi but should be relatively simple to port to other frameworks that
is built on top of the libcoap library such as ESP-IDF for the ESP32. 

## Client certificate and private key

The sample code reads the certificate and private key from the files `cert.crt` and `key.pem`. Both files 
must be PEM-encoded. The `cert.crt` contains the client certificate, intermediates and root and the `key.pem` 
file contains the private key.

Use the [span CLI](https://github.com/lab5e/spancli) to generate a certificate and key file.

## Building

Install libcoap headers:

`sudo dnf install libcoap-devel`

Build with `make`
