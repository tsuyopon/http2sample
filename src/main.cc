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

//#define READ_BUF_SIZE 4096
//#define BUF_SIZE 4097
#define READ_BUF_SIZE 32768
#define BUF_SIZE 32768
#define PORT 443
#define BINARY_FRAME_LENGTH 9


// ALPN識別子. h2
static const unsigned char protos[] = { 0x02, 0x68, 0x32 };
static const char cmp_protos[] = { 0x68, 0x32 };
static int protos_len = 3;

//ドラフト14を使う場合
// ALPN識別子. h2-14
//static const uint8_t protos[] = { 0x05, 0x68, 0x32, 0x2d, 0x31, 0x36 };
//static const uint8_t cmp_protos[] = { 0x68, 0x32, 0x2d, 0x31, 0x36 };
//static int protos_len = 6;

#define CLIENT_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

int get_error();
void close_socket(SOCKET socket, SSL_CTX *_ctx, SSL *_ssl);
static ssize_t to_hex(unsigned char *dst, size_t dst_len, unsigned char *src, size_t src_len);

// 3バイトのネットワークオーダーを4バイト整数へ変換する関数.
unsigned char* to_framedata3byte(unsigned char * &p, int &n);
void to_frametype(unsigned char * &p, unsigned char *type);
void to_frameflags(unsigned char * &p, unsigned char *flags);
void to_framestreamid(unsigned char * &p, unsigned int& streamid);

int sendSettingsAck(SSL *ssl);
int sendHeadersFrame(SSL *ssl, std::string host);
int sendGowayFrame(SSL *ssl);

/*
 *  HTTP/2 フレーム仕様: https://tools.ietf.org/html/rfc7540#section-4
 *  length(24) + type(8) + Flags(8) + R(1) + StreamID(31)
 *  (lengthにはフレームペイロード自体の9byteは含まれないことに注意すること)
 */
// FIXME: StreamIDは31なのにintで定義してる
unsigned char* createFramePayload (int length, char type, char flags, int streamid){
    unsigned char *frame;
    frame = static_cast<unsigned char*>(std::malloc(BINARY_FRAME_LENGTH));   // BINARY_FRAME_LENGTH = 9 byte

	// Relate: Values greater than 2^14 (16,384) MUST NOT be sent unless the receiver has set a larger value for SETTINGS_MAX_FRAME_SIZE. (sec4.1)

	// 最初の3byte(24bit)はLength
	// int(4byte)なので、1byte先から3byte分取得する)
	frame[0] = ((length>>16)&0xFF);
	frame[1] = ((length>>8)&0xFF);
	frame[2] = ((length)&0xFF);

	// フレームタイプ
	frame[3] = type;

	// Flags
	frame[4] = flags;

	// TODO: Reservedは省略した作りになっている。
	// R: A reserved 1-bit field. The semantics of this bit are undefined, and the bit MUST remain unset (0x0) when sending and MUST be ignored when receiving. (sec4.1)

	// intを各種バイトずつ敷き詰める。memcpyで4byteコピーを指定すると先頭ビットに1が配置されてしまうようでうまくいかない
	frame[5] = ((streamid>>24)&0xFF);
	frame[6] = ((streamid>>16)&0xFF);
	frame[7] = ((streamid>>8)&0xFF);
	frame[8] = ((streamid)&0xFF);

	return frame;
}

// HPACKの簡単なデータを作成する。
// ここで対応しているのは、以下のパターンのみ。
// しかし、headerまたはvalueが127文字を超過した際のパケットの整数表現に対応できていないという非常に簡易なもの
// https://tools.ietf.org/html/rfc7541#section-6.2.2
int createHpack(const std::string header, const std::string value, unsigned char* &dst){
    unsigned char *hpack;
    hpack = static_cast<unsigned char*>(std::malloc( 1 + 1 + header.length() + 1 + value.length()));
    hpack[0] = 0;
    hpack[1] = header.length();
    memcpy(hpack+2, header.c_str(), header.length());
    hpack[2+header.length()] = value.length();
    memcpy(hpack+2+header.length()+1, value.c_str(), value.length());

//    printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X\n", hpack[0], hpack[1],hpack[2],hpack[3],hpack[4],hpack[5],hpack[6],hpack[7],hpack[8]);
    dst = hpack;
//    printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X\n", dst[0], dst[1],dst[2],dst[3],dst[4],dst[5],dst[6],dst[7],dst[8]);
    return 1 + 1 + header.length() + 1 + value.length();
}


// フレームペイロード(9byte)を読み込む関数
int readFramePayload(SSL* ssl, unsigned char* p, int& payload_length, unsigned char* type, unsigned char* flags, unsigned int& streamid){  // TODO: unsigned intに変更した方がいいかも

	int r = 0;
	int ret = 0;
	bool b = false;
    while (1){

        r = SSL_read(ssl, p, BINARY_FRAME_LENGTH);
        printf("BINARY_FRAME: %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]);
        ret = SSL_get_error(ssl, r); 
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_READ:
                continue;
            default:
                if (r == -1){
                    printf("Error Occured: HEADER_FRAME SSL_read");
                    return ret;  // TODO: 後で綺麗にする
                }
        }
        if (b) break;
    }

	to_framedata3byte(p, payload_length);
	to_frametype(p, type);
	to_frameflags(p, flags);
	to_framestreamid(p, streamid);
	printf("streamid = %d\n\n", streamid);

	return ret;
}


// 一部の小さなフレーム用のデータでは、取得したコンテンツを解析して使います。このためのデータを取得します。
// 大きなデータはreadFrameContentsで読み込んでください。
int getFrameContentsIntoBuffer(SSL* ssl, int payload_length, unsigned char* retbuf){

	int r = 0;
	int ret = 0;
	unsigned char buf[BUF_SIZE] = { 0 };
	unsigned char* p = buf;
	unsigned int total_read_bytes = 0;

    while (payload_length > 0){

        p = buf;
        r = SSL_read(ssl, p, payload_length);
        ret = SSL_get_error(ssl, r);
        memcpy(retbuf+total_read_bytes, p, r);    // 読み込んんだサイズ分だけコピーする
        switch (ret){
            case SSL_ERROR_NONE:
                break;
            case SSL_ERROR_WANT_READ:
                continue;
            default:
                if (r == -1){
                    printf("Error Occured: payload contents SSL_read");
                    return ret;
                }
        }

        total_read_bytes += r;
        payload_length -= r;
    }
    return ret;
}

// フレームに含まれるコンテンツを読む。主にDATAやHEADERSなどの大きいデータ用途
// 現状skipしかしませんが。。。
int readFrameContents(SSL* ssl, int &payload_length, int print){

	int r = 0;
	int ret = 0;
	unsigned char buf[BUF_SIZE] = { 0 };
	unsigned char* p = buf;

    while (payload_length > 0){

        memset(buf, 0x00, BUF_SIZE);
        p = buf;

		// フレームで指定されたペイロード長がREAD_BUF_SIZEよりも小さい場合には、payload_lengthを指定しないと、フレームで指定されたペイロード長を超えたサイズを読み込むことになる。
		if(payload_length > READ_BUF_SIZE) {
			r = SSL_read(ssl, p, READ_BUF_SIZE);
		} else {
			r = SSL_read(ssl, p, payload_length);
		}
        ret = SSL_get_error(ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                break;
            case SSL_ERROR_WANT_READ:
                continue;
            default:
                if (r == -1){
                    printf("Error Occured: payload contents SSL_read");
                    return ret;
                }
        }

        payload_length -= r;

        printf("Rest payload_length = %d\n", payload_length);
        if(print) printf("%s", p);
    }
    return ret;
}

int writeFrame(SSL* &ssl, unsigned char* data, int &data_length){

	int r = 0;
	int ret = 0;
	bool b = false;
    while (1){

        r = SSL_write(ssl, data, data_length);
        ret = SSL_get_error(ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                if (r == -1){
                    printf("Error Occured: Preface SSL_write");
                    return ret;
                }
        }
        if (b) break;
    }
	return ret;
}


enum class FrameType {
	DATA = 0x0,
	HEADERS = 0x1,
	PRIORITY = 0x2,
	RST_STREAM = 0x3,
	SETTINGS = 0x4,
	PUSH_PROMISE = 0x5,
	PING = 0x6,
	GOAWAY = 0x7,
	WINDOW_UPDATE = 0x8,
	CONTINUATION = 0x9
};

// 読み込んだフレームに応じて、実行する処理を分岐するメインロジック
int readFrameLoop(SSL* ssl, std::string &host){

	int write_headers = 0;    // 初回のHEADERSフレームの書き込みを行ったかどうか判定するフラグ */
    int payload_length = 0;
	unsigned char type = 0;
	unsigned char flags = 0;
	unsigned int streamid = 0;
	unsigned char buf[BUF_SIZE] = {0};
	unsigned char* p = buf;

	while(1){
		type = 0;
		flags = 0;
		memset(buf, 0, BUF_SIZE);

		printf("\n\nreadFrameLoop: loop start\n");
		readFramePayload(ssl, p, payload_length, &type, &flags, streamid);
		printf("type=%d, payload_length=%d, flags=%d, streamid=%d\n", type, payload_length, type, streamid);

		if( type != 4 && type != 8){
			readFrameContents(ssl, payload_length, 1);
		}

		switch(static_cast<FrameType>(type)){
			// PING responses SHOULD be given higher priority than any other frame. (sec6.7)
			case FrameType::PING:
				printf("=== PING Frame Recieved ===\n");

				// If a PING frame is received with a stream identifier field value other than 0x0, the recipient MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR. (sec6.7)
				if(streamid != 0 ){
					// TBD
				}

				// Receipt of a PING frame with a length field value other than 8 MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR. (sec6.7)
				if( payload_length != 8 ){
					// TBD
				}

				// RESPONSE PING ACK
				unsigned char* headersframe;
				unsigned char* framepayload;
				int writelen;
				framepayload = createFramePayload(8 /* ping length */, static_cast<char>(FrameType::PING), 0x1 /* ACK */, 0 /*streamid*/);
				headersframe = static_cast<unsigned char*>(std::malloc(sizeof(unsigned char)*(BINARY_FRAME_LENGTH + 8)));
				memcpy(headersframe, framepayload, BINARY_FRAME_LENGTH);
				memset(headersframe+BINARY_FRAME_LENGTH, 0, 8);
				writelen = BINARY_FRAME_LENGTH+8;
				if( writeFrame(ssl, headersframe, writelen) < 0 ){
					// FIXME: errorとclose_socketへの対応が必要
					return -1;
				}
				break;
			case FrameType::DATA:
				printf("\n=== DATA Frame Recieved ===\n");
				// If an endpoint receives a SETTINGS frame whose stream identifier field is anything other than 0x0, the endpoint MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR. (sec6.5)
				if(streamid != 0 ){
					// TBD
				}

				// END_STREAM
				if( flags & 0x1 ){
					 printf("*** END_STREAM Recieved\n");
					return 0;
				}

				break;
				
			case FrameType::HEADERS:
				printf("=== HEADERS Frame Recieved ===\n");
				if( flags & 0x1 ) printf("*** END_STREAM Recieved\n");
				if( flags & 0x4 ) printf("*** END_HEADERS Recieved\n");
				if( flags & 0x8 ) printf("*** PADDED Recieved\n");
				if( flags & 0x20 ) printf("*** PRIORITY Recieved\n");

				break;

			case FrameType::PRIORITY:
				printf("=== PRIORITY Frame Recieved ===\n");
				/* do nothing */
				// フレームだけ読み飛ばす
				break;

			case FrameType::RST_STREAM:
				printf("=== RST_STREAM Frame Recieved ===\n");

				// If a RST_STREAM frame is received with a stream identifier of 0x0, the recipient MUST treat this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR. (sec6.4)
				if( streamid != 0 ){
					// TBD
				}

				// A RST_STREAM frame with a length other than 4 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR. (sec6.4)
				if( payload_length != 4 ){
					// TBD
				}
				break;

			case FrameType::SETTINGS:
				printf("=== SETTINGS Frame Recieved ===\n");

				getFrameContentsIntoBuffer(ssl, payload_length, p);

				int setting_num;
				setting_num = payload_length/6;
				printf("Recieved %d settings\n", setting_num);

				// SETTINGSフレームで取得した設定値があれば、表示する。
				while(setting_num){
					//printf("%02x %02x %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
					unsigned short identifier;
					unsigned int value;
					identifier = ((p[0] & 0xFF) << 8 ) + (p[1] & 0xFF);
					value = ( ( (p[2] & 0xFF) << 24 ) + ((p[3] & 0xFF) << 16 ) + ((p[4] & 0xFF) << 8 ) + ((p[5] & 0xFF) ));
					printf("identifier=%d, value=%d\n", identifier, value);
					p += 6;
					setting_num--;
				}

				// SETTINGSフレームには設定が0なら0octet、設定が1つなら6octet、2つなら12octetと6の倍数の値になることが保証されています。
				// A SETTINGS frame with a length other than a multiple of 6 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.
				if( payload_length % 6 != 0 ){
					printf("=== [ERROR] Invalid Settings Frame Recieved\n");
					return -1;
				}

				// SETTINGSフレームへの応答
				// TODO: Upon receiving the SETTINGS frame, the client is expected to honor any parameters established. (sec3.5)
				printf("=== SETTINGS Frame flags===\n");
				if(sendSettingsAck(ssl) < 0){
					// TBD
				}

				// 初回SETTINGSフレームを受信した後に、HEADERSフレームをリクエストする
				if(write_headers == 0){
					if(sendHeadersFrame(ssl, host) < 0){
						// TBD
					}
					write_headers = 1;
				}

				break;

			case FrameType::PUSH_PROMISE:
				printf("=== PUSH_PROMISE Frame Recieved ===\n");
				/* do nothing */
				// フレームだけ読み飛ばす
				break;

			case FrameType::GOAWAY:
				printf("=== GOAWAY Frame Recieved ===\n");
				break;

			case FrameType::WINDOW_UPDATE:
				printf("=== WINDOW_UPDATE Frame Recieved ===\n");
				getFrameContentsIntoBuffer(ssl, payload_length, p);
				unsigned int size_increment;;
				size_increment = ( ( (p[0] & 0xFF) << 24 ) + ((p[1] & 0xFF) << 16 ) + ((p[2] & 0xFF) << 8 ) + ((p[3] & 0xFF) ));
				printf("%02x %02x %02x %02x\n", p[0], p[1], p[2], p[3]);
				printf("window_size_increment = %d\n", size_increment);
				break;

			case FrameType::CONTINUATION:
				printf("=== CONTINUATION Frame Recieved ===\n");
				if(streamid == 0 ){
					printf("Invalid CONTINUATION Frame Recieved\n");
					// TBD
				}
				break;

			/* how to handle unknown frame type */
			default:
				printf("=== UNKNOWN Frame Recieved ===\n");
				break;

		}
	}
	return 0;  // FIXME

}

int main(int argc, char **argv)
{

    //------------------------------------------------------------
    // 接続先ホスト名.
    //------------------------------------------------------------
    //std::string host = "www.yahoo.co.jp";
    std::string host = "www.google.com";
    //std::string host = "www.youtube.com";
    //std::string host = "rakuten.co.jp";
    //std::string host = "www.nttdocomo.co.jp";
    //std::string host = "www.nifty.com";
    //std::string host = "www.cloudflare.com";
    //std::string host = "www.google.co.jp";
    //std::string host = "www.atmarkit.co.jp";

    //std::string host = "www3.nhk.or.jp";       // Error Occured: alpn_len
    //std::string host = "www.amazon.co.jp";   // Error Occured: alpn_len

    //std::string host = "b.hatena.ne.jp";  // SSL_Connect error
    //std::string host = "www.goo.ne.jp";       // HTTP/2未対応
    //std::string host = "www.livedoor.com";    // HTTP/2未対応
    //std::string host = "github.com";          // HTTP/2未対応

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

    //------------------------------------------------------------
    // wiresharkにHTTP/2としてTLSを解読させるためにrandomとmaster_secertを出力する。デバッグをしやすくするため。
    //------------------------------------------------------------
    unsigned char buf_raw_r[SSL3_RANDOM_SIZE];
    unsigned char buf_client_random[SSL3_RANDOM_SIZE*2+10];        // +1でいいかも
    unsigned char buf_raw_m[SSL_MAX_MASTER_KEY_LENGTH];
    unsigned char buf_master_key[SSL_MAX_MASTER_KEY_LENGTH*2+10];  // +1でいいかも
    ssize_t res;

    FILE *outputfile;         // 出力ストリーム
    outputfile = fopen("/Users/tsuyoshi/Desktop/tls_key.log", "a");

    size_t ssl_client_r = SSL_get_client_random(_ssl, buf_raw_r, SSL3_RANDOM_SIZE);
    res = to_hex(buf_client_random, sizeof(buf_client_random), buf_raw_r, ssl_client_r);
    res = fprintf(outputfile, "CLIENT_RANDOM %s ", buf_client_random);

    size_t ssl_client_m = SSL_SESSION_get_master_key(SSL_get_session(_ssl), buf_raw_m, SSL_MAX_MASTER_KEY_LENGTH);
    res = to_hex(buf_master_key, sizeof(buf_master_key), buf_raw_m, ssl_client_m);
    res = fprintf(outputfile, "%s\n", buf_master_key);

    fclose(outputfile);          // ファイルをクローズ(閉じる)

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
    unsigned char buf[BUF_SIZE] = { 0 };
    unsigned char* p = buf;
    bool b = false;
    int payload_length = 0;
    int frame_type = 0;
    int ret = 0;

	// 本当はwriteFrameへの第３引数を一気に渡したい
    printf("=== Start write HTTP/2 Preface string\n");
	int writelen;
	writelen = strlen(CLIENT_CONNECTION_PREFACE);
	if( writeFrame(_ssl, reinterpret_cast<unsigned char*>(const_cast<char*>(CLIENT_CONNECTION_PREFACE)), writelen) < 0 ){
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
	if( writeFrame(_ssl, settingframe, writelen) < 0 ){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
		return 0;
	}

	// メインループ
	readFrameLoop(_ssl, host);

	// GOAWAYフレームの送信
	if(sendGowayFrame(_ssl) < 0){
		error = get_error();
		close_socket(_socket, _ctx, _ssl);
	}

    close_socket(_socket, _ctx, _ssl);
    return 0;
}
//------------------------------------------------------------
// ACKの送信.
// ACKはSettingフレームを受け取った側が送る必要がある.
// ACKはSettingフレームのフラグに0x01を立ててpayloadを空にしたもの.
//
// フレームタイプは「0x04」
// 5バイト目にフラグ0x01を立てます。
//------------------------------------------------------------
// When this bit(ACK) is set, the payload of the SETTINGS frame MUST be empty.  (sec6.5)
int sendSettingsAck(SSL *ssl){
	const unsigned char settingframeAck[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
	printf("=== Start write SETTINGS frame ACK flags\n");
	int writelen = BINARY_FRAME_LENGTH;
	// MEMO: const unsigned char[9]は const_castで一気にunsigned char*へと変換できる。reinterpret_castは不要。
	if( writeFrame(ssl, const_cast<unsigned char*>(settingframeAck), writelen) < 0 ){
		// TBD: errorとclose_socketは入れる
		return -1;
	}
	return 0;
}

//------------------------------------------------------------
// HEADERSフレームの送信.
//
// フレームタイプは「0x01」
// このフレームに必要なヘッダがすべて含まれていてこれでストリームを終わらせることを示すために、
// END_STREAM(0x1)とEND_HEADERS(0x4)を有効にします。
// 具体的には5バイト目のフラグに「0x05」を立てます。
// ストリームIDは「0x01」を使います.
//
// ここまででヘッダフレームは「ペイロードの長さ(3バイト), 0x01, 0x05, 0x00, 0x00, 0x00, 0x01」になります.
//
//
// ●HTTP1.1でのセマンティクス
// 　　"GET / HTTP1/1"
// 　　"Host: nghttp2.org
//
// ●HTTP2でのセマンティクス
//      :method GET
//      :path /
//      :scheme https
//      :authority nghttp2.org
//
// 本来HTTP2はHPACKという方法で圧縮します.
// 今回は上記のHTTP2のセマンティクスを圧縮なしで記述します.
//
// 一つのヘッダフィールドの記述例
//
// |0|0|0|0|      0|   // 最初の4ビットは圧縮に関する情報、次の4ビットはヘッダテーブルのインデクス.(今回は圧縮しないのですべて0)
// |0|            7|   // 最初の1bitは圧縮に関する情報(今回は0)、次の7bitはフィールドの長さ
// |:method|           // フィールドをそのままASCIIのオクテットで書く。
// |0|            3|   // 最初の1bitは圧縮に関する情報(今回は0)、次の7bitはフィールドの長さ
// |GET|               // 値をそのままASCIIのオクテットで書く。
//
// 上記が一つのヘッダフィールドの記述例で、ヘッダーフィールドの数だけこれを繰り返す.
//
// See: https://tools.ietf.org/html/rfc7541#appendix-B
//------------------------------------------------------------

// バイト数を変更したら配列数を変更してください、また、SSL_wirteにわたすバイト数も変更してください。
// フレームの先頭3byteはフレームに含まれるバイト数です。全体で74ならば、そこからヘッダフレーム9byteを引いた64(0x00, 0x00, 0x41)を指定します。
//    const unsigned char headersframe[74] = {
//        0x00, 0x00, 0x41, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01,   // ヘッダフレーム(**バイト数を変更したら上位３ビットを変更してください**)
//        0x00,                                                   // 圧縮情報
//        0x07, 0x3a, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,         // 7 :method
//        0x03, 0x47, 0x45, 0x54,                                 // 3 GET
//        0x00,                                                   // 圧縮情報
//        0x05, 0x3a, 0x70, 0x61, 0x74, 0x68,                     // 5 :path
//        0x01, 0x2f,                                             // 1 /
//        0x00,                                                   // 圧縮情報
//        0x07, 0x3a, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x65,         // 7 :scheme
//        0x05, 0x68, 0x74, 0x74, 0x70, 0x73,                     // 5 https
//        0x00,                                                   // 圧縮情報
//        0x0a, 0x3a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79,           // 10 :authority
//        0x0f, 0x77, 0x77, 0x77, 0x2e, 0x79, 0x61, 0x68, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x2e, 0x6a, 0x70 };  // 15.www.yahoo.co.jp
int sendHeadersFrame(SSL *ssl, std::string host){

    int ret_value, ret_value2, ret_value3, ret_value4, total;
    unsigned char* query1;
    unsigned char* query2;
    unsigned char* query3;
    unsigned char* query4;
    ret_value  = createHpack(std::string(":method"),    std::string("GET"), query1);
    ret_value2 = createHpack(std::string(":path"),      std::string("/"), query2);
    ret_value3 = createHpack(std::string(":scheme"),    std::string("https"), query3);
    ret_value4 = createHpack(std::string(":authority"), host, query4);
    total = ret_value + ret_value2 + ret_value3 + ret_value4;

    unsigned char* framepayload;
    framepayload = createFramePayload(total, 0x01, 0x05, 1);  // 第２引数: フレームタイプはHEADER「0x01」、第３引数: END_STREAM(0x1)とEND_HEADERS(0x4)を有効にします、第４引数はstramID

	unsigned char* headersframe;
	headersframe = static_cast<unsigned char*>(std::malloc(sizeof(unsigned char)*(total+BINARY_FRAME_LENGTH)));
	int offset;
	memcpy(headersframe, framepayload, BINARY_FRAME_LENGTH);
	offset = BINARY_FRAME_LENGTH;
	memcpy(headersframe+offset, query1, ret_value);
	offset += ret_value;
	memcpy(headersframe+offset, query2, ret_value2);
	offset += ret_value2;
	memcpy(headersframe+offset, query3, ret_value3);
	offset += ret_value3;
	memcpy(headersframe+offset, query4, ret_value4);

    printf("=== Start write HEADERS frame\n");
	int writelen = total+BINARY_FRAME_LENGTH;
	if( writeFrame(ssl, headersframe, writelen) < 0 ){
		return -1;
	}
	return 0;
}

//------------------------------------------------------------
// GOAWAYの送信.
//
// これ以上データを送受信しない場合はGOAWAYフレームを送信します.
// フレームタイプは「0x07」
// ストリームIDは「0x00」(コネクション全体に適用するため)
//------------------------------------------------------------
int sendGowayFrame(SSL *ssl){
	printf("\n=== Start write GOAWAY frame\n");
	const char goawayframe[17] = { 0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
	int writelen = sizeof(goawayframe);
	// MEMO: 一旦constを除去して、その後char*からunsigned char*への変換が必要。(一気にreinterpret_castやconst_castでの変換はできない)
	if( writeFrame(ssl, reinterpret_cast<unsigned char *>(const_cast<char*>(goawayframe)), writelen) < 0 ){
		return -1;
	}
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

unsigned char* to_framedata3byte(unsigned char * &p, int &n){
	printf("to_framedata3byte: %02x %02x %02x\n", p[0], p[1], p[2]);
    u_char buf[4] = {0};      // bufを4byte初期化
    memcpy(&(buf[1]), p, 3);  // bufの2byte目から4byteめまでをコピー
    memcpy(&n, buf, 4);       // buf領域を全てコピー
    n = ntohl(n);             // ネットワークバイトオーダーを変換
    p += 3;                   // 読み込んだ3byteをスキップする      // MEMO: 引数を&で参照にしないとポインタの加算が行われない。
    return p;
}

// パケットからフレームタイプを取得する
void to_frametype(unsigned char * &p, unsigned char *type){
	printf("to_frametype: %02x\n", p[0]);
	*type = p[0];
	p++;
}

// パケットからフレームタイプのflagsを取得する
void to_frameflags(unsigned char * &p, unsigned char *flags){   // to_frametypeと共通
	printf("to_frameflags: %02x\n", p[0]);
	*flags = p[0];
	p++;
}

// パケットからstreamidを取得する
void to_framestreamid(unsigned char * &p, unsigned int& streamid){
	streamid = 0;
	// see: How to make int from char[4]? (in C)
	//   https://stackoverflow.com/questions/17602229/how-to-make-int-from-char4-in-c/17602505
	printf("to_framestreamid: %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3]);
	streamid = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3]);
	p += 4;
}

static ssize_t to_hex(unsigned char *dst, size_t dst_len, unsigned char *src, size_t src_len) {
	ssize_t wr = 0;
	for (size_t i = 0; i < src_len; i++) {
//		printf("%02X", src[i]);
		int w = snprintf((char *) dst + wr, dst_len - (size_t) wr, "%02x", src[i]);
		if (w <= 0)
			return -1;
		wr += (ssize_t) w;
	}
//	printf("\n");
	return wr;
}
