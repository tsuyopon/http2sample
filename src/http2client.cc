//
// HTTP/2クライアント
// 接続先は引数で指定することができます。
// $ ./http2client www.google.com
//
// コンパイル: $ make
//
//*****************************************************
// OpenSSL1.1.0以上を使用.
//*****************************************************

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <string>
#include <map>
#include <vector>
#include <iostream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#define SOCKET int
#define SD_BOTH SHUT_WR

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Definitions.h"
#include "FrameProcessor.h"
#include "DebugUtils.h"
#include "ErrorCodes.h"
#include "HuffmanCode.h"
#include "RequestUtil.h"
#include "ConnectionState.h"

int get_error();
void close_socket(SOCKET socket, SSL_CTX *_ctx, SSL *_ssl);

void handler(int signal) {
	fprintf(stderr, "signal handler reveived %d signal. exited\n", signal);
	exit(1);
}

int main(int argc, char **argv)
{

	std::map<std::string, std::string> headers;
	headers[":method"] = "GET";
	headers[":path"] = "/";
	headers[":scheme"] = "https";

	// 引数の取得
	int opt;
	std::string host ="";
	std::string path = "/";
	std::string scheme = "https";
	std::string method = "GET";
	std::string url = "https://www.google.com/";

	// Retrieve the options:
	while ( (opt = getopt(argc, argv, "m:u:H:")) != -1 ) {  // for each option...
		switch ( opt ) {
			case 'm':  // method option
					if( strcmp(optarg, "GET") != 0 && strcmp(optarg, "POST") != 0 && strcmp(optarg, "PUT") != 0 && strcmp(optarg, "DELETE") != 0){
						printf("unmatch method case exited.\n");
						exit(1);
					} 
					printf("method recieved. %s\n", optarg);
					headers[":method"] = optarg;
					method = optarg;
				break;
			case 'u':  // url option
					printf("URL(u) recieved. %s\n", optarg);
					url = optarg;
					RequestUtil::parseUrl(url, scheme, host, path);
					headers[":scheme"] = scheme.c_str();
					headers[":authority"] = host.c_str();
					headers[":path"] = path.c_str();
				break;
			case 'H':  // header option
			{
					printf("HEADER(H) recieved. %s\n", optarg);
					url = optarg;
					std::string header_value;
					std::string header_name;
					RequestUtil::parseHeader(optarg, header_value, header_name);
					headers[header_value] = header_name;
			}
				break;
			case '?':  // unknown option...
					std::cerr << "Unknown option: '" << char(optopt) << "'!" << std::endl;
					exit(1);
				break;
		}
	}

	if(argc == 1){
		//------------------------------------------------------------
		// 接続先ホスト名.
		//------------------------------------------------------------
		//host = "www.yahoo.co.jp";
		host = "www.google.com";
		//host = "www.nifty.com";
		//host = "www.cloudflare.com";
		//host = "www.google.co.jp";
		//host = "www.atmarkit.co.jp";

		// WINDOW_UPDATEを実施しないと正しく帰ってこないサイト
		//host = "www.youtube.com";
		//host = "auctions.yahoo.co.jp";

		// ALPNエラー
		//host = "rakuten.co.jp";
		//host = "www3.nhk.or.jp";
		//host = "www.amazon.co.jp";

		// HTTP/2未対応
		//host = "www.goo.ne.jp";
		//host = "www.livedoor.com";
		//host = "github.com";

		// SSL Connect Error
		//host = "b.hatena.ne.jp";  // SSL_Connect error

		// 不明なエラー
		//host = "www.nttdocomo.co.jp";  // ３、４回に1度正しくデータが帰ってきてる

		headers[":authority"] = host.c_str();
	}

	std::cout << "===== REQUEST INFORMATION START =====" << std::endl;
	for( auto i = headers.begin(); i != headers.end() ; ++i ) {
		std::cout << i->first << " " << i->second << "\n";
	}
	std::cout << "===== REQUEST INFORMATION END =====" << std::endl;

	std::vector<std::map<std::string, std::string>> headermap;
	headermap.push_back(headers);

	// Test
	std::map<std::string, std::string> headers1;
	headers1[":method"] = "GET";
	headers1[":path"] = "/";
	headers1[":scheme"] = "https";
	headers1[":authority"] = "gyao.yahoo.co.jp";
	headermap.push_back(headers1);

	std::map<std::string, std::string> headers2;
	headers2[":method"] = "GET";
	headers2[":path"] = "/";
	headers2[":scheme"] = "https";
	headers2[":authority"] = "auctions.yahoo.co.jp";
	headermap.push_back(headers2);

	std::map<std::string, std::string> headers3;
	headers3[":method"] = "GET";
	headers3[":path"] = "/";
	headers3[":scheme"] = "https";
	headers3[":authority"] = "finance.yahoo.co.jp";
	headermap.push_back(headers3);

	//------------------------------------------------------------
	// シグナルの登録
	//------------------------------------------------------------
	struct sigaction action;
	sigset_t sigset;
	sigemptyset(&sigset);
	action.sa_handler = handler;
	action.sa_flags = 0;
	action.sa_mask = sigset;

	// RSTでのコネクション切断後にwriteした場合にはSIGPIPEを定義しないとハンドリングできない
	// http://doi-t.hatenablog.com/entry/2014/06/10/033309
	sigaction(SIGPIPE, &action, NULL);

	//------------------------------------------------------------
	// SSLの準備.
	//------------------------------------------------------------
	SSL *_ssl;
	SSL_CTX *_ctx;

	// SSLライブラリの初期化.
	SSL_library_init();

	// エラーを文字列化するための準備.
	SSL_load_error_strings();

	// グローバルコンテキスト初期化.
	// Implementations of HTTP/2 MUST use TLS version 1.2 [TLS12] or higher for HTTP/2 over TLS. (sec9.2)
	const SSL_METHOD *meth = TLS_method();   // TLS_method()にしたらmaster_secretが取得できなくなった。。。
	_ctx = SSL_CTX_new(meth);

	int error = 0;
	struct hostent *hp;
	struct sockaddr_in addr;
	SOCKET _socket;

	if (!(hp = gethostbyname(host.c_str()))){
		printf("Error Occured: gethostbyname");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr = *(struct in_addr*)hp->h_addr_list[0];
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);

	if ((_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0){
		printf("Error Occured: socket");
		return -1;
	}
	if (connect(_socket, (struct sockaddr *)&addr, sizeof(addr))<0){
		printf("Error Occured: connect");
		return -1;
	}

	// sslセッションオブジェクトを作成する.
	_ssl = SSL_new(_ctx);

	// ソケットと関連づける.
	SSL_set_fd(_ssl, _socket);

	//------------------------------------------------------------
	// HTTP2の準備.
	//
	// プロトコルのネゴシエーションにALPNという方法を使います。
	// 具体的にはTLSのClientHelloのALPN拡張領域ににこれから使うプロトコル名を記述します.
	// SPDYではNPNという方法が使われましたが、現在のHTTP2仕様ではNPNは廃止されています.
	//
	// protosには文字列ではなくバイナリで、「0x02, 'h','2'」と指定する。
	// 最初の0x02は「h2」の長さを表している.
	//------------------------------------------------------------
	// HTTP/2 over TLS uses the "h2" protocol identifier.  The "h2c" protocol identifier MUST NOT be sent by a client or selected by a server(sec3.3)
	SSL_set_alpn_protos(_ssl, protos, protos_len);

	// HTTP/2 clients MUST indicate the target domain name when negotiating TLS. (sec9.2)
	SSL_set_tlsext_host_name(_ssl, host.c_str());

	// SSL接続.
	if (SSL_connect(_ssl) <= 0){
		printf("Error Occured: SSL_connect");
		error = get_error();
		::shutdown(_socket, SD_BOTH);
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	// 採用されたALPNを確認する.
	// implementations that support HTTP/2 over TLS MUST use protocol negotiation in TLS. (sec3.4)
	const unsigned char  *ret_alpn;
	unsigned int  alpn_len;
	SSL_get0_alpn_selected(_ssl, &ret_alpn, &alpn_len);

	if ((int)alpn_len < protos_len - 1){
		printf("Error Occured: alpn_len");
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	if (memcmp(ret_alpn, cmp_protos, alpn_len) != 0){
		printf("Error Occured: alpn selection");
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	// wiresharkでHTTP/2パケットを解釈させるためにSSLKEYLOGFILEに暗号解読に必要な情報をwiresharkフォーマットで記載
	DebugUtils::createSslKeyLogFile(_ssl, SSLKEYLOGFILE);

	// Once TLS negotiation is complete, both the client and the server MUST send a connection preface (sec3.3)
	// The client sends the client connection preface immediately upon receipt of a 101 (Switching Protocols) response (indicating a successful upgrade) or as the first application data octets of a TLS connection. (sec3.5)
	int writelen;
	writelen = strlen(CLIENT_CONNECTION_PREFACE);
	printf(MAZENDA_BR("=== Start write HTTP/2 Preface string === (length=%d)\n"), writelen);
	if( FrameProcessor::writeFrame(_ssl, reinterpret_cast<unsigned char*>(const_cast<char*>(CLIENT_CONNECTION_PREFACE)), writelen) < 0 ){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	// FIXME: shared_ptrを利用する
	ConnectionState* con_state = new ConnectionState(false);
	con_state->set_send_initial_frames();

	// To avoid unnecessary latency, clients are permitted to send additional frames to the server immediately after sending the client connection preface, without waiting to receive the server connection preface. (sec3.5)
	// SETTINGSフレームの送信を行う

	std::map<uint16_t, uint32_t> setmap;
	con_state->getSettingsMap(setmap);

	if(FrameProcessor::sendSettingsFrame(_ssl, setmap) < 0){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	// メインループ
	int loop_return;
	loop_return = FrameProcessor::readFrameLoop(con_state, _ssl, headermap);
	// After receiving a RST_STREAM on a stream, the receiver MUST NOT send additional frames for that stream, with the exception of PRIORITY. 
	if (loop_return == static_cast<int>(FrameType::RST_STREAM)){
		printf(CYAN_BR("=== RST_STREAM Recieved"));
		return 0;
	}

	// GOAWAYフレームの送信
	// FIXME: 複数のstreamに対応
	const unsigned int last_streamid = 1;
	const unsigned int error_code = 0;
	if(FrameProcessor::sendGowayFrame(_ssl, last_streamid, error_code) < 0){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	close_socket(_socket, _ctx, _ssl);
	return 0;
}

void close_socket(SOCKET socket, SSL_CTX *_ctx, SSL *_ssl){
	SSL_shutdown(_ssl);
	SSL_free(_ssl);
	::shutdown(socket, SD_BOTH);
	::close(socket);
	SSL_CTX_free(_ctx);
	ERR_free_strings();
}

int get_error(){
	return errno;
}
