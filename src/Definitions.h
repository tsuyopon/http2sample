#pragma once

#define PORT 443
#define BINARY_FRAME_LENGTH 9
#define SSLKEYLOGFILE "/Users/tsuyoshi/Desktop/tls_key.log"
#define CLIENT_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ALPN識別子. h2
static const unsigned char protos[] = { 0x02, 0x68, 0x32 };
static const char cmp_protos[] = { 0x68, 0x32 };
static int protos_len = 3;
