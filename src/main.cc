//
// HTTP/2クライアントの最小実装サンプル
// 
// 接続先はhttps://www.yahoo.co.jp/
//
// コンパイル: $ g++ -lssl -lcrypto -lstdc++ tlsclient.cc  
//
//*****************************************************
// OpenSSL1.1.0以上を使用.
//*****************************************************

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string>

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

// ALPN識別子. h2
static const unsigned char protos[] = { 0x02, 0x68, 0x32 };
static const char cmp_protos[] = { 0x68, 0x32 };
static int protos_len = 3;

int get_error();
void close_socket(SOCKET socket, SSL_CTX *_ctx, SSL *_ssl);

int main(int argc, char **argv)
{

	std::string host;
	if(argc == 2){
		host = argv[1];
	} else {
		//------------------------------------------------------------
		// 接続先ホスト名.
		//------------------------------------------------------------
		host = "www.yahoo.co.jp";
		//host = "www.google.com";
		//host = "www.youtube.com";
		//host = "www.nttdocomo.co.jp";  // ３、４回に1度正しくデータが帰ってきてる
		//host = "www.nifty.com";
		//host = "www.cloudflare.com";
		//host = "www.google.co.jp";
		//host = "www.atmarkit.co.jp";

		//host = "rakuten.co.jp";      // Error Occured: alpn_len
		//host = "www3.nhk.or.jp";     // Error Occured: alpn_len
		//host = "www.amazon.co.jp";   // Error Occured: alpn_len

		//host = "b.hatena.ne.jp";  // SSL_Connect error
		//host = "www.goo.ne.jp";       // HTTP/2未対応
		//host = "www.livedoor.com";    // HTTP/2未対応
		//host = "github.com";          // HTTP/2未対応
	}
	printf("Requesting... hostname = %s\n", host.c_str());

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
    const SSL_METHOD *meth = TLSv1_2_method();   // TLS_method()にしたらmaster_secretが取得できなくなった。。。
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

    //------------------------------------------------------------
    // これからHTTP2通信を開始する合図.
    //
    // 24オクテットのバイナリを送信します
    // PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
    //------------------------------------------------------------
    // Once TLS negotiation is complete, both the client and the server MUST send a connection preface (sec3.3)
    //
    //  The client sends the client connection preface immediately upon receipt of a 101 (Switching Protocols) response (indicating a successful upgrade) or as the first application data octets of a TLS connection. (sec3.5)
    int r = 0;

    // MEMO: 以下の2つはもともとcharで定義していたが、unsignedにしないと %02Xで %0x2bではなく、0xffffffa0のように表示されてしまうため。参考: https://oshiete.goo.ne.jp/qa/864334.html
//    unsigned char buf[BUF_SIZE] = { 0 };
//    unsigned char* p = buf;
    bool b = false;

	// 本当はwriteFrameへの第３引数を一気に渡したい
    printf("=== Start write HTTP/2 Preface string\n");
	int writelen;
	writelen = strlen(CLIENT_CONNECTION_PREFACE);
	if( FrameProcessor::writeFrame(_ssl, reinterpret_cast<unsigned char*>(const_cast<char*>(CLIENT_CONNECTION_PREFACE)), writelen) < 0 ){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

    //------------------------------------------------------------
    // 全てのデータはバイナリフレームで送受信される
    // バイナリフレームは共通の9バイトヘッダと、データ本体であるpayloadを持つ
    //
    // ●ヘッダ部分のフォーマット
    //
    //   1-3バイト目  payloadの長さ。長さにヘッダの9バイトは含まれない。.
    //   4バイト目　フレームのタイプ.
    //   5バイト目　フラグ.
    //   6-9バイト目　ストリームID.(最初の1bitは予約で必ず0)
    //
    //  |Length(24bit)|Type(8bit)|Flags(8bit)|Reserve(1bit)|Stream Identifier(31bit)|
    //  |Frame Payload(Lengthバイト分)|
    //
    //
    // [フレームのタイプ]
    //
    // DATA(0x00)  リクエストボディや、レスポンスボディを転送する
    // HEADERS(0x01)  圧縮済みのHTTPヘッダーを転送する
    // PRIORITY(0x02)  ストリームの優先度を変更する
    // RST_STREAM(0x03)  ストリームの終了を通知する
    // SETTINGS(0x04)  接続に関する設定を変更する
    // PUSH_PROMISE(0x05)  サーバーからのリソースのプッシュを通知する
    // PING(0x06)  接続状況を確認する
    // GOAWAY(0x07)  接続の終了を通知する
    // WINDOW_UPDATE(0x08)   フロー制御ウィンドウを更新する
    // CONTINUATION(0x09)  HEADERSフレームやPUSH_PROMISEフレームの続きのデータを転送する
    //
    // それぞれのリクエストやレスポンスにはストリームIDが付与される.
    // クライアントから発行されるストリームIDは奇数.
    // サーバーから発行されるストリームIDは偶数.
    // ストリームには優先順位が付けられています.
    // 今回はストリームID「1」だけを使用します.
    //------------------------------------------------------------

    //------------------------------------------------------------
    // HTTP2通信のフロー
    //
    // まず最初にSettingフレームを必ず交換します.
    // Settingフレームを交換したら、設定を適用したことを伝えるために必ずACKを送ります.
    //
    // Client -> Server  SettingFrame
    // Client <- Server  SettingFrame
    // Client -> Server  ACK
    // Client <- Server  ACK
    //
    // Client -> Server  HEADERS_FRAME (GETなど)
    // Client <- Server  HEADERS_FRAME (ステータスコードなど)
    // Client <- Server  DATA_FRAME (Body)
    // 
    // Client -> Server  GOAWAY_FRAME (送信終了)
    //------------------------------------------------------------

    //------------------------------------------------------------
    // Settingフレームの送信.
    // フレームタイプは「0x04」
    // 全てデフォルト値を採用するためpayloadは空です。
    // SettingフレームのストリームIDは0です.
    //
    // 今回は空ですがSettingフレームのpayloadは次のフォーマットです.
    //
    // |Identifer(16bit)|Value(32bit)|
    // 上記を設定値の数だけ連結させ、最終的な長さをヘッダフレームのLengthに記述します.
    //
    // Identiferは次のものが定義されています。
    // SETTINGS_HEADER_TABLE_SIZE (0x1)  初期値は 4,096 オクテット
    // SETTINGS_ENABLE_PUSH (0x2)  初期値は1
    // SETTINGS_MAX_CONCURRENT_STREAMS (0x3)  初期状態では無制限
    // SETTINGS_INITIAL_WINDOW_SIZE (0x4)   初期値は 2^16-1 (65,535)
    // SETTINGS_MAX_FRAME_SIZE (0x5)    初期値は 2^24-1 (16777215)
    // SETTINGS_MAX_HEADER_LIST_SIZE (0x6)   初期値は無制限
    //------------------------------------------------------------
    // To avoid unnecessary latency, clients are permitted to send additional frames to the server immediately after sending the client connection preface, without waiting to receive the server connection preface. (sec3.5)
    unsigned char settingframe[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};
    printf("=== Start write SETTINGS frame\n");
	writelen = BINARY_FRAME_LENGTH;
	if( FrameProcessor::writeFrame(_ssl, settingframe, writelen) < 0 ){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	// メインループ
	int loop_return;
	loop_return = FrameProcessor::readFrameLoop(_ssl, host);
	// After receiving a RST_STREAM on a stream, the receiver MUST NOT send additional frames for that stream, with the exception of PRIORITY. 
    int ret = 0;
	if (ret == static_cast<int>(FrameType::RST_STREAM)){
		printf("=== Start write SETTINGS frame\n");
		return 0;
	}

	// GOAWAYフレームの送信
	if(FrameProcessor::sendGowayFrame(_ssl) < 0){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
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
