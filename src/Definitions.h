#pragma once

#define PORT 443
#define BINARY_FRAME_LENGTH 9
#define SSLKEYLOGFILE "/Users/tsuyoshi/Desktop/tls_key.log"
#define CLIENT_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ALPN識別子. h2
static const unsigned char protos[] = { 0x02, 0x68, 0x32 };
static const char cmp_protos[] = { 0x68, 0x32 };
static int protos_len = 3;

// FIXME: あとで移動させたいかも
#define RED_BR(STR)     "\e[31m" STR "\e[m\n"
#define GREEN_BR(STR)   "\e[32m" STR "\e[m\n"
#define ORANGE_BR(STR)  "\e[33m" STR "\e[m\n"
#define BLUE_BR(STR)    "\e[34m" STR "\e[m\n"
#define MAZENDA_BR(STR) "\e[35m" STR "\e[m\n"
#define CYAN_BR(STR)    "\e[36m" STR "\e[m\n"
