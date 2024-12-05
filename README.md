# CoAP Server for Testing Connection ID

This project provides a CoAP server setup for testing **DTLS Connection ID (CID)** on a Debian system. Follow the instructions below to clone, build, and run the server.

---

## Requirements

- **libcoap** must be installed
- **Autotools** for building

---

## Installation and Setup

### Step 1: Clone the wolfSSL Repository
```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
git remote add julek https://github.com/julek-wolfssl/wolfssl.git
git fetch julek dtls-server-demux
git checkout master
git merge julek/dtls-server-demux
sudo apt update
sudo apt install autoconf automake libtool

./autogen.sh
CFLAGS=-DWOLFSSL_STATIC_PSK ./configure --enable-debug --enable-dtls --enable-dtls13 --enable-dtlscid --enable-opensslextra --enable-psk
make
sudo make install
```
to compile the code run (your paths might differ):
```bash
gcc server-dtls-coap.c -o server-dtls-coap -I /usr/local/include -L/usr/local/lib -Wl,-rpath=/usr/local/lib -lwolfssl -lcoap3

```
