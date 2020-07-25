#pragma once

#include <string>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>

class ConnectionState;

#define READ_BUF_SIZE 32768
#define BUF_SIZE 32768
#define BIT(num)                 ((unsigned int)1 << (num))

// Frame Flags
#define FLAGS_ACK                      BIT(0)   // defined in SETTINGS, PING
#define FLAGS_END_STREAM               BIT(0)
#define FLAGS_END_HEADERS              BIT(2)
#define FLAGS_PADDED                   BIT(3)
#define FLAGS_PRIORITY                 BIT(5)

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
	CONTINUATION = 0x9,
	ALTSVC = 0xa, /* RFC7838 */
	ORIGIN = 0xc  /* RFC8336 */
};

enum SettingsId : uint16_t
{
	SETTINGS_HEADER_TABLE_SIZE = 0x1,
	SETTINGS_ENABLE_PUSH = 0x2,
	SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
	SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
	SETTINGS_MAX_FRAME_SIZE = 0x5,
	SETTINGS_MAX_HEADER_LIST_SIZE = 0x6
};

class FrameProcessor {
public:
	static int readFrameLoop(ConnectionState* con_state, SSL* ssl, const std::map<std::string, std::string> &headers, bool server=false);
	// write
	static unsigned char* createFramePayload(unsigned int length, char type, char flags, unsigned int streamid);
	static int sendSettingsFrame(SSL *ssl, std::map<uint16_t, uint32_t>& setmap);
	static int sendSettingsAck(SSL *ssl);
	static int sendDataFrame(SSL *ssl);
	static int sendHeadersFrame(SSL *ssl, const std::map<std::string, std::string> &headers, uint8_t flags);
	static int sendGowayFrame(SSL *ssl, const unsigned int last_streamid, const unsigned int error_code);
	static int sendWindowUpdateFrame(SSL *ssl, unsigned int &streamid, const unsigned int increment_size);
	static int sendRstStreamFrame(SSL *ssl, unsigned int &streamid, unsigned int error_code);
	static int writeFrame(SSL* &ssl, unsigned char* data, int &data_length);
	// read
	static int readFramePayload(SSL* ssl, unsigned char* p, unsigned int& payload_length, unsigned char* type, unsigned char* flags, unsigned int& streamid);
	static int getFrameContentsIntoBuffer(SSL* ssl, unsigned int payload_length, unsigned char* retbuf);
	static int readFrameContents(SSL* ssl, unsigned int &payload_length, int print);

private:
	static void _copy2byteIntoUint16(unsigned char *p, uint16_t &dst);
	static void _copy4byteIntoUint32(unsigned char *p, unsigned int &dst);
	static void _copyUint16Into2byte(unsigned char *p, const uint16_t &src);
	static void _copyUint32Into4byte(unsigned char *p, const unsigned int &src);
	static unsigned char* _to_framedata3byte(unsigned char * &p, unsigned int &n);
	static void _to_frametype(unsigned char * &p, unsigned char *type);
	static void _to_frameflags(unsigned char * &p, unsigned char *flags);
	static void _to_framestreamid(unsigned char * &p, unsigned int& streamid);
	// 必要最小限の引数だけを追加
	static int _rcv_ping_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length);
	static int _rcv_data_frame(SSL* ssl, unsigned int &payload_length, unsigned int flags);
	static int _rcv_headers_frame(ConnectionState* con_state, SSL* ssl, unsigned int &payload_length, unsigned int flags, unsigned char* &p);
	static void _rcv_priority_frame(SSL* ssl, unsigned int &payload_length);
	static int _rcv_rst_stream_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned char* &p);
	static int _rcv_settings_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned int flags, unsigned char* &p);
	static void _rcv_push_promise_frame(SSL* ssl, unsigned int &payload_length);
	static void _rcv_goaway_frame(SSL* ssl, unsigned int &payload_length, unsigned char* &p);
	static void _rcv_window_update_frame(SSL* ssl, unsigned int &payload_length, unsigned char* &p);
	static int _rcv_continuation_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length);
	static void _rcv_altsvc_frame(SSL* ssl, unsigned int &payload_length);
	static void _rcv_origin_frame(SSL* ssl, unsigned int &payload_length);
};
