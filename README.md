# CoAP Server for Testing Connection ID

This project provides a CoAP server setup for testing **DTLS Connection ID (CID)** on a Debian system. Follow the instructions below to clone, build, and run the server.

---

## Requirements

- **libcoap** must be installed
- **Autotools** for building (sudo apt install autoconf automake libtool)


---

## Installation and Setup

### Step 1: Clone the wolfSSL Repository
```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-debug --enable-dtls --enable-dtls13 --enable-dtlscid --enable-opensslextra --enable-psk --enable-rpk --enable-curve25519 && make && make install
make
sudo make install
```
to compile the code run (your paths might differ):
```bash
gcc server-dtls-coap.c -o server-dtls-coap -I /usr/local/include -L/usr/local/lib -Wl,-rpath=/usr/local/lib -lwolfssl -lcoap3
```
To run server:
```bash
./server-dtls-coap
```
