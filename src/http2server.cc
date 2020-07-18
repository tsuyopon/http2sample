#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include <getopt.h>
//
#include <string>
//#include <map>
//#include <iostream>
//
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
//#include <netdb.h>
//#include <fcntl.h>
//#include <signal.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SD_BOTH SHUT_WR
#define SOCKET int

// ALPN識別子. h2
static const unsigned char protos[] = { 0x02, 0x68, 0x32 };
static const char cmp_protos[] = { 0x68, 0x32 };
static int protos_len = 3;

int get_error();
//void close_socket(SOCKET socket, SSL_CTX *ctx, SSL *ssl);


uint8_t readFileCheck(char* &filename){
	FILE *fp;
	fp = fopen(filename,"r");
	if(fp == NULL){
		printf("open file failed. %s\n", filename);
		return -1;
	}
	return 0;

}

int main(int argc, char **argv)
{

	char msg[1024];
	char* crt_file = const_cast<char*>("testkeys/server.crt");
	char* key_file = const_cast<char*>("testkeys/server.key");

	//------------------------------------------------------------
	// SSLの準備.
	//------------------------------------------------------------
	SSL *ssl;
	SSL_CTX *ctx;

	// SSLライブラリの初期化.
	SSL_library_init();

	// エラーを文字列化するための準備.
	SSL_load_error_strings();

	// グローバルコンテキスト初期化.
	// Implementations of HTTP/2 MUST use TLS version 1.2 [TLS12] or higher for HTTP/2 over TLS. (sec9.2)
	const SSL_METHOD *meth = TLS_server_method();   // FIXME: 1.3も使えるようにあとで修正する
	ctx = SSL_CTX_new(meth);

	if( readFileCheck(crt_file) != 0  || readFileCheck(key_file) != 0 ){
		printf("certificate files read failed\n");
		exit(1);
	}
	SSL_CTX_use_certificate_file(ctx, crt_file, SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);

	int serverfd;

	if( (serverfd = socket(PF_INET, SOCK_STREAM, 0) ) < 0 ){
		printf("Error calling socket()\n");
		exit(1);
	}

	struct sockaddr_in addr;
	socklen_t size = sizeof(struct sockaddr_in);
	char buf[1024];
	char body[] = "hello world";
	char header[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\nConnection: Close\r\n";

	int port = 443;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if(bind(serverfd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
		printf("Error calling bind()\n");
		exit(1);
	}

	int backlog = 10;
	if(listen(serverfd, backlog) < 0){
		printf("Error calling listen()\n");
		close(serverfd);
		exit(1);
	}

	while(1) {

		int client;
		client = accept(serverfd, (struct sockaddr*)&addr, &size);
		printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		int ret;
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		ret = SSL_accept(ssl);

		if (ret > 0) {
			printf("ACCEPT SUCCESSED ret=%d\n", ret);
			SSL_read(ssl, buf, sizeof(buf));
			printf("%s\n", buf);
			snprintf(msg, sizeof(msg), "%s\r\n%s", header, body);
			SSL_write(ssl, msg, strlen(msg));
		} else {
			printf("ACCEPT ERROR OCCURED ret=%d\n", ret);
		}

		int sd;
		sd = SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sd);
	}

	close(serverfd);
	SSL_CTX_free(ctx);

}

//void close_socket(SOCKET socket, SSL_CTX *ctx, SSL *ssl){
//	SSL_shutdown(ssl);
//	SSL_free(ssl);
//	::shutdown(socket, SD_BOTH);
//	::close(socket);
//	SSL_CTX_free(ctx);
//	ERR_free_strings();
//}
//
//int get_error(){
//	return errno;
//}
