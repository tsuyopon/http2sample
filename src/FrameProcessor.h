#pragma once

#include <string>
#include <map>
#include <list>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Definitions.h"
#include "ErrorCodes.h"
#include "Hpack.h"

//#define READ_BUF_SIZE 4096
//#define BUF_SIZE 4097
#define READ_BUF_SIZE 32768
#define BUF_SIZE 32768

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
	static int readFrameLoop(SSL* ssl, const std::map<std::string, std::string> &headers, bool server=false);
	// write
	static unsigned char* createFramePayload (int length, char type, char flags, int streamid);
	static int sendSettingsFrame(SSL *ssl, std::map<uint16_t, uint32_t>& setmap);
	static int sendSettingsAck(SSL *ssl);
	static int sendHeadersFrame(SSL *ssl, const std::map<std::string, std::string> &headers);
	static int sendGowayFrame(SSL *ssl);
	static int writeFrame(SSL* &ssl, unsigned char* data, int &data_length);
	// read
	static int readFramePayload(SSL* ssl, unsigned char* p, unsigned int& payload_length, unsigned char* type, unsigned char* flags, unsigned int& streamid);
	static int getFrameContentsIntoBuffer(SSL* ssl, unsigned int payload_length, unsigned char* retbuf);
	static int readFrameContents(SSL* ssl, unsigned int &payload_length, int print);
	static unsigned char* to_framedata3byte(unsigned char * &p, unsigned int &n);
	static void to_frametype(unsigned char * &p, unsigned char *type);
	static void to_frameflags(unsigned char * &p, unsigned char *flags);
	static void to_framestreamid(unsigned char * &p, unsigned int& streamid);
private:
	// 必要最小限の引数だけを追加
	static int _rcv_ping_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length);
	static int _rcv_data_frame(SSL* ssl, unsigned int &payload_length, unsigned int flags);
	static void _rcv_headers_frame(SSL* ssl, unsigned int &payload_length, unsigned int flags, unsigned char* &p);
	static void _rcv_priority_frame(SSL* ssl, unsigned int &payload_length);
	static int _rcv_rst_stream_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned char* &p);
	static int _rcv_settings_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned int flags, unsigned char* &p);
	static void _rcv_push_promise_frame(SSL* ssl, unsigned int &payload_length);
	static void _rcv_goaway_frame(SSL* ssl, unsigned int &payload_length, unsigned char* &p);
	static void _rcv_window_update_frame(SSL* ssl, unsigned int &payload_length, unsigned char* &p);
	static int _rcv_continuation_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length);
};
