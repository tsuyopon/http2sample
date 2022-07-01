#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Definitions.h"
#include "FrameProcessor.h"
#include "ConnectionState.h"
#include "DebugUtils.h"

#define SD_BOTH SHUT_WR
#define SOCKET int

void handler(int signal) {
	fprintf(stderr, "signal handler reveived %d signal\n", signal);
}

// SSL_CTX_set_alpn_select_cbに指定するコールバック関数
static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
    
	unsigned int protlen = 0;
	const unsigned char *prot;
	const char *h2alpn = "h2";      // http2であれば受け付けるようにする
	const char *h11alpn= "http/1.1";      // "http/1.1"であれば受け付けるようにする

	for (prot = in; prot < in + inlen; prot += protlen) {
		protlen = *prot++;
		if (in + inlen < prot + protlen)
			return SSL_TLSEXT_ERR_NOACK;    // ALPN protocol not selected.

		if (protlen == strlen(h2alpn) && memcmp(prot, h2alpn, protlen) == 0) {
			printf("ALPN callback matched %s\n", h2alpn);
			// out, outlenに何も指定しないとSSL_TLSEXT_ERR_NOACK扱いとなるので注意
			// ここで指定された値がClientHelloに対する応答としてServerHelloメッセージで返されることになる
			*out = prot;
			*outlen = protlen;
			return SSL_TLSEXT_ERR_OK;      // ALPN protocol selected.
		} else if (protlen == strlen(h11alpn) && memcmp(prot, h11alpn, protlen) == 0) {
			*out = prot;
			*outlen = protlen;
			return SSL_TLSEXT_ERR_OK;      // ALPN protocol selected.
		}
	}

	printf("[ERROR] ALPN callback not matched\n");
	return SSL_TLSEXT_ERR_NOACK;           // ALPN protocol not selected.
}

uint8_t readFileCheck(char* &filename){
	FILE *fp;
	fp = fopen(filename,"r");
	if(fp == NULL){
		printf("[ERROR] open file failed. %s\n", filename);
		return -1;
	}
	return 0;

}

int main(int argc, char **argv)
{

	char* crt_file = const_cast<char*>("testkeys/server.crt");
	char* key_file = const_cast<char*>("testkeys/server.key");

	//------------------------------------------------------------
	// シグナルの登録
	//------------------------------------------------------------
	struct sigaction action;
	sigset_t sigset;
	sigemptyset(&sigset);
	action.sa_handler = handler;
	action.sa_flags = 0;
	action.sa_mask = sigset;
	sigaction(SIGPIPE, &action, NULL);

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
	//const SSL_METHOD *meth = TLS_server_method();   // FIXME: これでTLS1.2が使えるがSSLKEYLOGが未対応
	const SSL_METHOD *meth = TLS_method();
	ctx = SSL_CTX_new(meth);

	// ALPNが指定された場合に呼ばれるコールバックを登録します。
	SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

	// 証明書・秘密鍵ファイルのreadチェック
	if( readFileCheck(crt_file) != 0  || readFileCheck(key_file) != 0 ){
		printf("[ERROR] certificate files read failed\n");
		exit(1);
	}

	// サーバ証明書の登録
	if (SSL_CTX_use_certificate_file(ctx, crt_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// サーバ秘密鍵の登録
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	SOCKET serverfd;
	if( (serverfd = socket(PF_INET, SOCK_STREAM, 0) ) < 0 ){
		printf("[ERROR] calling socket()\n");
		exit(1);
	}

	struct sockaddr_in addr;

	int port = 443;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if(bind(serverfd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
		printf("[ERROR] calling bind()\n");
		exit(1);
	}

	int backlog = 10;
	if(listen(serverfd, backlog) < 0){
		printf("[ERROR] calling listen()\n");
		close(serverfd);
		exit(1);
	}

	socklen_t size = sizeof(struct sockaddr_in);
	char buf[1024];
	while(1) {

		printf("accept start...\n");
		int client;
		client = accept(serverfd, (struct sockaddr*)&addr, &size);
		printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		int ret;
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		ret = SSL_accept(ssl);

		if (ret > 0) {
			printf("ACCEPT SUCCESSED ret=%d\n", ret);
			DebugUtils::createSslKeyLogFile(ssl, SSLKEYLOGFILE);
			const unsigned char *data;
			unsigned len = 0;
			SSL_get0_alpn_selected(ssl, &data, &len);

			unsigned char* alpn_str = static_cast<unsigned char*>(malloc(len+1));
			if( data == nullptr ){
				printf("[ERROR] ALPN: protocol is not selected\n");
			} else if (memcmp(alpn_str, "h2", 2)){
				memcpy(alpn_str, data, len);
				alpn_str[len] = '\0';
				printf("ALPN: protocol selected = %s\n", alpn_str);

				// FIXME: want read等の追加
				// preface分チェック
				SSL_read(ssl, buf, strlen(CLIENT_CONNECTION_PREFACE));
				if(memcmp(buf, CLIENT_CONNECTION_PREFACE, strlen(CLIENT_CONNECTION_PREFACE)) == 0 ){
					printf("matched h2 preface\n");
				} else {
					// error
				}
				printf("%s\n", buf);

				std::map<uint16_t, uint32_t> setmap;
				ConnectionState* con_state = new ConnectionState(true);
				con_state->getSettingsMap(setmap);

				if(FrameProcessor::sendSettingsFrame(ssl, setmap) < 0){
					// TBD
				}

				if( FrameProcessor::readFrameLoopServer(con_state, ssl) < 0){
					return -1;
				}

				// GOAWAYフレームの送信
				// FIXME: 複数のstreamに対応
				const unsigned int last_streamid = 1;
				const unsigned int error_code = 0;
				if(FrameProcessor::sendGowayFrame(ssl, last_streamid, error_code) < 0){
					return 0;
				}

			} else if (memcmp(alpn_str, "http1.1", 7)){
				char msg[1024];
				char body[] = "hello world HTTP1.1";
				char header[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\nConnection: Close\r\n";
				snprintf(msg, sizeof(msg), "%s\r\n%s", header, body);
				SSL_write(ssl, msg, strlen(msg));
			} else {
				printf("Unsupported ALPN");
			}
			printf("Finished Session\n");

		} else {
			printf("[ERROR] ACCEPT ERROR OCCURED ret=%d\n", ret);
		}

		SSL_shutdown(ssl);
		SSL_free(ssl);
	}

	::shutdown(serverfd, SD_BOTH);
	close(serverfd);
	SSL_CTX_free(ctx);
	ERR_free_strings();
}
