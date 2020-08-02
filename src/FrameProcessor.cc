#include "FrameProcessor.h"
#include "ConnectionState.h"
#include "StreamState.h"
#include "Definitions.h"
#include "ErrorCodes.h"
#include "Hpack.h"

#include <list>
#include <string.h>
#include <arpa/inet.h>

// 読み込んだフレームに応じて、実行する処理を分岐するメインロジック
// serverとclientから利用できるようにフラグをもつ
int FrameProcessor::readFrameLoop(ConnectionState* con_state, SSL* ssl, const std::map<std::string, std::string> &headers){

	unsigned char buf[BUF_SIZE] = {0};
	unsigned char* p = buf;
	unsigned int recv_data = 0;

//	StreamState* str_state = new StreamState(con_state->get_next_streamid());
//	con_state->createStream();

	int tmpflag = 0;

	while(1){
		unsigned int payload_length = 0;
		unsigned char type = 0;
		unsigned char flags = 0;
		unsigned int streamid = 0;
		memset(buf, 0, BUF_SIZE);

		if( FrameProcessor::readFramePayload(ssl, p, payload_length, &type, &flags, streamid) != SSL_ERROR_NONE ){
			return 0;
		}

		StreamState* str_state = nullptr;
		con_state->findStreamByStreamId(streamid, str_state);

		printf(ORANGE_BR("##### readFramePayload Start: type=%d, payload_length=%d, flags=%d, streamid=%d"), type, payload_length, type, streamid);

		switch(static_cast<FrameType>(type)){
			// PING responses SHOULD be given higher priority than any other frame. (sec6.7)
			case FrameType::PING:
				if( FrameProcessor::_rcv_ping_frame(ssl, streamid, payload_length) < 0 ){
					// FIXME
					return -1;
				}
				break;
			case FrameType::DATA:
				recv_data = payload_length;
				FrameProcessor::_rcv_data_frame(str_state, ssl, streamid, payload_length, flags, p);

				// コネクションレベルのWINDOW_UPDATE通知判定
				if(con_state->incrementPeerPayloadAndCheckWindowUpdateIsNeeded(recv_data)){
					unsigned int connection_streamid = 0;
					FrameProcessor::sendWindowUpdateFrame(ssl, connection_streamid, con_state->get_peer_consumer_data_bytes());  // コネクションレベルの通知
					con_state->reset_peer_consumer_data_bytes();
				}

				// ストリームレベルのWINDOW_UPDATE通知判定
				if(str_state->incrementPeerPayloadAndCheckWindowUpdateIsNeeded(recv_data)){
					FrameProcessor::sendWindowUpdateFrame(ssl, streamid, str_state->get_peer_consumer_data_bytes());  // コネクションレベルの通知
					str_state->reset_peer_consumer_data_bytes();
				}
				break;
				
			case FrameType::HEADERS:
			{

				// HEADERSフレームの2度目の受信をエラーにする
				if( str_state != nullptr && str_state->getRecieveHeaders() == true ){
					// FIXME
					printf(RED_BR("HEADER FRAME RECIEVED TWICE ERROR"));
				}

				// HEADERSフレームを受信したサーバは、クライアントの新規ストリームを生成する
				if(con_state->get_is_server()){
					con_state->createStreamById(streamid, str_state);
				}

				// クライアントで、END_HEADERSを受信したら終了
				int retdata = FrameProcessor::_rcv_headers_frame(str_state, ssl, streamid, payload_length, flags, p);
				if( !con_state->get_is_server() && retdata == 1){
					printf("Client: recieved 1 from _rcv_headers_frame\n");
					return 0;
				}

				// TBD: とりあえずスタブで簡単なものを返す(END_HEADERS等のフラグはチェックしない)
				if(con_state->get_is_server() && str_state->checkPeerHeadersRecieved() ){
					printf(ORANGE_BR("\tServer Header Frame Recieved"));
					// send headers frame

					std::map<std::string, std::string> headers;
					headers[":status"] = "200";
					headers["content-type"] = "text/plain";
					FrameProcessor::sendHeadersFrame(str_state, ssl, streamid, headers, FLAGS_END_STREAM|FLAGS_END_HEADERS);

					// send data frame
					FrameProcessor::sendDataFrame(ssl);

					return 0;
				}

				break;
			}

			case FrameType::PRIORITY:
				FrameProcessor::_rcv_priority_frame(ssl, payload_length);
				break;

			case FrameType::RST_STREAM:
				if(FrameProcessor::_rcv_rst_stream_frame(ssl, streamid, payload_length, p) < 0){
					// TBD: error
				}
				return static_cast<int>(FrameType::RST_STREAM);

			case FrameType::SETTINGS:
				if(FrameProcessor::_rcv_settings_frame(ssl, streamid, payload_length, flags, p) < 0){
					// TBD: error
				}
				if(!con_state->get_first_settings_frame()) con_state->set_first_settings_frame();

				break;

			case FrameType::PUSH_PROMISE:
				FrameProcessor::_rcv_push_promise_frame(ssl, payload_length);
				break;

			case FrameType::GOAWAY:
				FrameProcessor::_rcv_goaway_frame(ssl, payload_length, p);
				return 0;

			case FrameType::WINDOW_UPDATE:
				FrameProcessor::_rcv_window_update_frame(ssl, streamid, payload_length, p);
				break;

			case FrameType::CONTINUATION:
				if(FrameProcessor::_rcv_continuation_frame(str_state, ssl, streamid, payload_length, flags, p) == 2 ){
					// TBD: error

					// FIXME: とりあえず暫定のを返す
					std::map<std::string, std::string> headers;
					headers[":status"] = "200";
					headers["content-type"] = "text/plain";
					FrameProcessor::sendHeadersFrame(str_state, ssl, streamid, headers, FLAGS_END_STREAM|FLAGS_END_HEADERS);
					return static_cast<int>(FrameType::CONTINUATION);
				}
				break;

			case FrameType::ALTSVC:
				FrameProcessor::_rcv_altsvc_frame(ssl, payload_length);
				break;

			case FrameType::ORIGIN:
				FrameProcessor::_rcv_origin_frame(ssl, payload_length);
				break;

			/* how to handle unknown frame type */
			default:
				printf(RED_BR("=== UNKNOWN Frame Recieved ==="));
				FrameProcessor::readFrameContents(ssl, payload_length, 1);
				break;

		}
		printf("\n");

		// FIXME: delete tmpflag
		// クライアントの場合、SETTINGSフレームを受信後であれば、リクエストを送付できる。
		if(tmpflag == 0 && !con_state->get_is_server() && con_state->get_first_settings_frame()){

			printf("wirte header frame start");

			// FIXME: 一時的フラグ
			tmpflag = 1;

			// DELETE lator
			std::map<std::string, std::string> headers;
			headers[":method"] = "GET";
			headers[":path"] = "/";
			headers[":scheme"] = "https";
			headers[":authority"] = "gyao.yahoo.co.jp";
			
			StreamState* str_state;
			con_state->createStream(str_state);
			sendHeadersFrame(str_state, ssl, str_state->getStreamId(), headers, FLAGS_END_STREAM|FLAGS_END_HEADERS);

			std::map<std::string, std::string> headers2;
			headers2[":method"] = "GET";
			headers2[":path"] = "/";
			headers2[":scheme"] = "https";
			headers2[":authority"] = "www.yahoo.co.jp";
			StreamState* str_state2;
			con_state->createStream(str_state2);
			sendHeadersFrame(str_state2, ssl, str_state2->getStreamId(), headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);

			std::map<std::string, std::string> headers3;
			headers3[":method"] = "GET";
			headers3[":path"] = "/";
			headers3[":scheme"] = "https";
			headers3[":authority"] = "www.yahoo.co.jp";
			StreamState* str_state3;
			con_state->createStream(str_state3);
			sendHeadersFrame(str_state3, ssl, str_state3->getStreamId(), headers3, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                       sendHeadersFrame(str_state, ssl, 3, headers, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                       sendHeadersFrame(str_state, ssl, 5, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                       sendHeadersFrame(str_state, ssl, 7, headers, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                       headers2[":method"] = "GET";
//                                       headers2[":path"] = "/";
//                                       headers2[":scheme"] = "https";
//                                       headers2[":authority"] = "gyao.yahoo.co.jp";
//                                       sendHeadersFrame(str_state, ssl, 9, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                      headers2[":authority"] = "auctions.yahoo.co.jp";
//                                      sendHeadersFrame(str_state, ssl, 11, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                      headers2[":authority"] = "finance.yahoo.co.jp";
//                                      sendHeadersFrame(str_state, ssl, 13, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                      headers2[":authority"] = "security.yahoo.co.jp";
//                                      sendHeadersFrame(str_state, ssl, 15, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                     headers2[":authority"] = "shopping.yahoo.co.jp";
//                                     sendHeadersFrame(str_state, ssl, 17, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                     headers2[":authority"] = "tv.yahoo.co.jp";
//                                     sendHeadersFrame(str_state, ssl, 19, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                     headers2[":authority"] = "travel.yahoo.co.jp";
//                                     sendHeadersFrame(str_state, ssl, 21, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                     headers2[":authority"] = "movies.yahoo.co.jp";
//                                     sendHeadersFrame(str_state, ssl, 23, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                     headers2[":authority"] = "tv.yahoo.co.jp";
//                                     //headers2[":authority"] = "gyao.yahoo.co.jp";
//                                     sendHeadersFrame(str_state, ssl, 25, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                     headers2[":authority"] = "transit.yahoo.co.jp";
//                                     sendHeadersFrame(str_state, ssl, 27, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
//                                     headers2[":authority"] = "fortune.yahoo.co.jp";
//                                     sendHeadersFrame(str_state, ssl, 29, headers2, FLAGS_END_STREAM|FLAGS_END_HEADERS);
		}

		if( streamid != 0 ){
			if( str_state->getStreamStatus() == Http2State::closed ){
				con_state->deleteStream(streamid);
			}

			printf(RED_BR("concurrent num = %d\n"), con_state->get_concurrent_num());
			// FIXME: この位置で本当にいいの? stream=0でRST_STREAMを受信するときも考慮したい
			if( con_state->get_concurrent_num() == 0 ){
				return 0;
			}

		}

	}

	return 0;  // FIXME
}


int FrameProcessor::_rcv_ping_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length){
	printf(CYAN_BR("=== PING Frame Recieved === (length=%d, streamid=%d)"), payload_length, streamid);
	FrameProcessor::readFrameContents(ssl, payload_length, 1);

	// If a PING frame is received with a stream identifier field value other than 0x0, the recipient MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR. (sec6.7)
	if(streamid != 0 ){
		// TBD
		return -1;
	}

	// Receipt of a PING frame with a length field value other than 8 MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR. (sec6.7)
	if( payload_length != 8 ){
		// TBD
		return -1;
	}

	// RESPONSE PING ACK
	unsigned char* headersframe;
	unsigned char* framepayload;
	int writelen;
	framepayload = FrameProcessor::createFramePayload(8 /* ping length */, static_cast<char>(FrameType::PING), FLAGS_ACK, 0 /*streamid*/);
	headersframe = static_cast<unsigned char*>(std::malloc(sizeof(unsigned char)*(BINARY_FRAME_LENGTH + 8)));
	memcpy(headersframe, framepayload, BINARY_FRAME_LENGTH);
	memset(headersframe+BINARY_FRAME_LENGTH, 0, 8);
	writelen = BINARY_FRAME_LENGTH+8;
	if( FrameProcessor::writeFrame(ssl, headersframe, writelen) < 0 ){
		// FIXME: errorとclose_socketへの対応が必要
		return -1;
	}
	return 0;
}

int FrameProcessor::_rcv_data_frame(StreamState* str_state, SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned int flags, unsigned char* &p){
	printf(CYAN_BR("\n=== DATA Frame Recieved === (length=%d, flags=0x%02x, streamid=%d)"), payload_length, flags, streamid);

	// 本文の読み込み
	FrameProcessor::readFrameContents(ssl, payload_length, 1);

	if( flags & FLAGS_PADDED ){
		printf(ORANGE_BR("\tPADDED Recieved"));
		// 1byte分paddingを読み進める
		p++;
		payload_length--;
	}

	// END_STREAM(この処理は分岐を抜けるので、本文読み込み以降で実施)
	if( flags & FLAGS_END_STREAM ){
		str_state->setRecieveEndStream();
		printf(ORANGE_BR("\n\tEND_STREAM Recieved"));
		return 1;
	}


	return  0;

}

int FrameProcessor::_rcv_headers_frame(StreamState* str_state, SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned int flags, unsigned char* &p){

	str_state->setRecieveHeaders();
	printf(CYAN_BR("=== HEADERS Frame Recieved === (payload_length=%d, flags=0x%02x, streamid=%d)"), payload_length, flags, streamid);
	if( flags & FLAGS_END_STREAM ) {
		printf(ORANGE_BR("\tEND_STREAM Recieved"));
		str_state->setRecieveEndStream();
	}

	if( flags & FLAGS_END_HEADERS ){
		printf(ORANGE_BR("\tEND_HEADERS Recieved\n"));
		str_state->setRecieveEndHeaders();
	}

	bool padded = false;
	bool priority = false;
	if( flags & FLAGS_PADDED ){
		printf(ORANGE_BR("\tPADDED Recieved"));
		padded = true;
	}
	if( flags & FLAGS_PRIORITY ){
		printf(ORANGE_BR("\tPRIORITY Recieved"));
		priority = true;
	}

	// FIXME: Hpack表現は複数バイトに跨るパターンもあるので、全受信した(END_HEADERS=1)までデータを蓄積した後でチェックすることが望ましいと思われる。ただ、CONTINUATIONヘと続くパターンも別途考慮が必要となる。
	getFrameContentsIntoBuffer(ssl, payload_length, p);

	// padded と priority分を差し引く
	// FIXME: 以下の２つは未対応(ビットが立っていれば、その処理に必要なパケットはそのまま読み飛ばす)
	if(padded){
		p++;   // Pad Length(8bit)
		payload_length--;
	}
	if(priority){
		p += 5;  // E(1bit) + StreamDependency(31bit) + Weight(8bit)
		payload_length -= 5;
	}

	str_state->setHeaderBuffer(p, payload_length);

	// END_HEADERSとEND_STREAMがセットされたら終了させる
	if( str_state->getRecieveEndHeaders() && str_state->getRecieveEndStream() ){
		Hpack::readHpackHeaders(payload_length, p);
		// 処理は終了
		return 1;
	}

	if( str_state->getRecieveEndHeaders() ){
		// 次はDATAフレームを受け取ってから
		Hpack::readHpackHeaders(payload_length, p);
	} else {
		printf(ORANGE_BR("\tNext Continuation"));
		// 次はCONTINUATIONが処理する
	}

	return 0;

}

void FrameProcessor::_rcv_priority_frame(SSL* ssl, unsigned int &payload_length){
	printf(CYAN_BR("=== PRIORITY Frame Recieved === (payload_length=%d)"), payload_length);
	FrameProcessor::readFrameContents(ssl, payload_length, 1);
	/* do nothing */
	// フレームだけ読み飛ばす
}

int FrameProcessor::_rcv_rst_stream_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned char* &p){
	printf(CYAN_BR("=== RST_STREAM Frame Recieved === (payload_length=%d, streamid=%d"), payload_length, streamid);

	// If a RST_STREAM frame is received with a stream identifier of 0x0, the recipient MUST treat this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR. (sec6.4)
	if( streamid != 0 ){
		printf(RED_BR("[ERROR] invalid RST_STREAM. This message must be PROTOCOL_ERROR. streamid=%d"), streamid);
		// TBD
		return -1;
	}

	// A RST_STREAM frame with a length other than 4 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR. (sec6.4)
	if( payload_length != 4 ){
		printf(RED_BR("[ERROR] invalid RST_STREAM. FRAME_SIZE_ERROR"));
		// TBD
		return -1;
	}

	getFrameContentsIntoBuffer(ssl, payload_length /* 4 */, p);
	unsigned int error_code = 0;
	_copy4byteIntoUint32(&(p[0]), error_code);
	printf(ORANGE_BR("error_code = %d, message = %s"), error_code, ErrorMessages[error_code].c_str());
	return 0;

}

int FrameProcessor::_rcv_settings_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned int flags, unsigned char* &p){
	printf(CYAN_BR("=== SETTINGS Frame Recieved === (payload_length=%d, flags=0x%02x, streamid=%d)"), payload_length, flags, streamid);

	// If an endpoint receives a SETTINGS frame whose stream identifier field is anything other than 0x0, the endpoint MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR. (sec6.5)
	if(streamid != 0 ){
		 printf(RED_BR("[ERROR] invalid DATA Frame. PROTOCOL_ERROR"));
		// TBD
	}

	FrameProcessor::getFrameContentsIntoBuffer(ssl, payload_length, p);

	int setting_num;
	setting_num = payload_length/6;
	printf(ORANGE_BR("\tRecieved %d settings"), setting_num);

	// SETTINGSフレームで取得した設定値があれば、表示する。
	while(setting_num){
		//printf("%02x %02x %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
		unsigned short identifier = 0;
		unsigned int value = 0;
		_copy2byteIntoUint16(&(p[0]), identifier);
		_copy4byteIntoUint32(&(p[2]), value);
		printf(ORANGE_BR("\tidentifier=%d, value=%d"), identifier, value);
		p += 6;
		setting_num--;
	}

	// SETTINGSフレームには設定が0なら0octet、設定が1つなら6octet、2つなら12octetと6の倍数の値になることが保証されています。
	// A SETTINGS frame with a length other than a multiple of 6 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.
	if( payload_length % 6 != 0 ){
		printf(RED_BR("=== [ERROR] Invalid Settings Frame Recieved"));
		return -1;
	}

	// SETTINGSフレームへの応答
	// TODO: Upon receiving the SETTINGS frame, the client is expected to honor any parameters established. (sec3.5)
	if( payload_length != 0 && flags != FLAGS_ACK ){ // ACKの場合以外(長さは0以外で、flgsが0x01である)に、ACKを応答する。
		if(FrameProcessor::sendSettingsAck(ssl) < 0){
			// TBD
			return -1;
		}
	}
	return 0;

}

void FrameProcessor::_rcv_push_promise_frame(SSL* ssl, unsigned int &payload_length){
	printf(CYAN_BR("=== PUSH_PROMISE Frame Recieved === (payload_length=%d)"), payload_length);
	FrameProcessor::readFrameContents(ssl, payload_length, 1);
	/* do nothing */
	// フレームだけ読み飛ばす
}

void FrameProcessor::_rcv_goaway_frame(SSL* ssl, unsigned int &payload_length, unsigned char* &p){
	printf(CYAN_BR("=== GOAWAY Frame Recieved === (payload_length=%d)"), payload_length);
	getFrameContentsIntoBuffer(ssl, payload_length, p);
	unsigned int last_streamid = 0;
	unsigned int error_code = 0;
	// GOAWAYパケットの最初の4byteはlast_stream_id、次の4byteはerror_code、その後additional debug dataが続く
	_copy4byteIntoUint32(&(p[0]), last_streamid);
	_copy4byteIntoUint32(&(p[4]), error_code);
	printf(ORANGE_BR("last_streamid = %d, error_code = %d message = %s"), last_streamid, error_code, ErrorMessages[error_code].c_str());
}

void FrameProcessor::_rcv_window_update_frame(SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned char* &p){
	printf(CYAN_BR("=== WINDOW_UPDATE Frame Recieved === (payload_length=%d, streamid=%d)"), payload_length, streamid);
	getFrameContentsIntoBuffer(ssl, payload_length, p);
	unsigned int size_increment = 0;
	_copy4byteIntoUint32(&(p[0]), size_increment);
//	printf("%02x %02x %02x %02x\n", p[0], p[1], p[2], p[3]);
	printf(ORANGE_BR("\twindow_size_increment = %d"), size_increment);
}

int FrameProcessor::_rcv_continuation_frame(StreamState* str_state, SSL* ssl, unsigned int &streamid, unsigned int &payload_length, unsigned int flags, unsigned char* &p){
	printf(CYAN_BR("=== CONTINUATION Frame Recieved === (payload_length=%d, flags=0x%02x, streamid=%d"), payload_length, flags, streamid);

	if(streamid == 0 ){
		printf(RED_BR("Invalid CONTINUATION Frame Recieved"));
		// TBD
		return -1;
	}
	// TODO: Any number of CONTINUATION frames can be sent, as long as the preceding frame is on the same stream and is a HEADERS, PUSH_PROMISE, or CONTINUATION frame without the END_HEADERS flag set.

	if( flags & FLAGS_END_STREAM ) {
		printf(ORANGE_BR("\tEND_STREAM Recieved"));
		str_state->setRecieveEndStream();
	}

	if( flags & FLAGS_END_HEADERS ){
		printf(ORANGE_BR("\tEND_HEADERS Recieved"));
		str_state->setRecieveEndHeaders();
	}

	// FIXME: HEADERSのCONTINUATIONしか対応していない
	getFrameContentsIntoBuffer(ssl, payload_length, p);
	str_state->setHeaderBuffer(p, payload_length);

	if( str_state->getRecieveEndHeaders() ){
		Hpack::readHpackHeaders(str_state->getHeaderBufferSize(), str_state->getHeaderBuffer());  // FIXME: lock必要かも
		return 2;
	} else {
		printf(ORANGE_BR("\tRecieve Next Continuation"));
		return 1;
	}

	// FIXME: 戻り値適当

//	FrameProcessor::readFrameContents(ssl, payload_length, 1);
	return 0;
}

void FrameProcessor::_rcv_altsvc_frame(SSL* ssl, unsigned int &payload_length){
	printf(CYAN_BR("=== ALTSVC Frame Recieved === (payload_length=%d)"), payload_length);
	FrameProcessor::readFrameContents(ssl, payload_length, 1);
	/* do nothing */
	// フレームだけ読み飛ばす
}

void FrameProcessor::_rcv_origin_frame(SSL* ssl, unsigned int &payload_length){
	printf(CYAN_BR("=== ORIGIN Frame Recieved === (payload_length=%d)"), payload_length);
	FrameProcessor::readFrameContents(ssl, payload_length, 1);
	/* do nothing */
	// フレームだけ読み飛ばす
}

//////////////////////////
// WRITE
//////////////////////////
/*
 *	HTTP/2 フレーム仕様: https://tools.ietf.org/html/rfc7540#section-4
 *	length(24) + type(8) + Flags(8) + R(1) + StreamID(31)
 *	(lengthにはフレームペイロード自体の9byteは含まれないことに注意すること)
 */
// FIXME: StreamIDは31なのにintで定義してる
unsigned char* FrameProcessor::createFramePayload(unsigned int length, char type, char flags, unsigned int streamid){
	unsigned char *frame;
	frame = static_cast<unsigned char*>(std::malloc(BINARY_FRAME_LENGTH));	 // BINARY_FRAME_LENGTH = 9 byte

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
	_copyUint32Into4byte((&frame[5]), streamid);

	return frame;
}

//------------------------------------------------------------
// Settingフレームの送信.
//     ただし、ACKを送付する場合には、FrameProcessor::sendSettingsAckを使うこと
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
int FrameProcessor::sendSettingsFrame(SSL *ssl, std::map<uint16_t, uint32_t>& setmap){

	int writelen;
	writelen = BINARY_FRAME_LENGTH + setmap.size() * 6;
	unsigned char *settingframe;
	settingframe = static_cast<unsigned char*>(malloc(writelen));

	// length
	settingframe[0] = 0;
	settingframe[1] = 0;
	settingframe[2] = setmap.size()*6;  // 1byteだけでsettingは表現できる

	settingframe[3] = 4;  // type
	settingframe[4] = 0;  // flags

	// streamid
	const unsigned int streamid = 0;   // FIXME: とりあえずアテで入れる
	_copyUint32Into4byte(&(settingframe[5]), streamid);

	// Note: C/C++ packing signed char into int
    //    https://stackoverflow.com/questions/2437283/c-c-packing-signed-char-into-int
	// add setting frame
	int cnt = 0;
	for (auto i = setmap.begin(); i != setmap.end(); ++i) {
		_copyUint16Into2byte(&(settingframe[9+6*cnt]), i->first);  // pack uint16_t
		_copyUint32Into4byte(&(settingframe[11+6*cnt]), i->second);  // pack uint32_t(int)
		cnt++;
	}

    printf(MAZENDA_BR("=== Start write SETTINGS frame === (length=%d, flags=0x%02x, streamid=%d)\n"), writelen, settingframe[4], streamid);
	if( FrameProcessor::writeFrame(ssl, settingframe, writelen) < 0 ){
		return -1;
	}
	return 0;
}

//------------------------------------------------------------
// Settingsフレーム(ACKの送信)
// ACKはSettingフレームを受け取った側が送る必要がある.
// ACKはSettingフレームのフラグに0x01を立ててpayloadは必ず空でなければならない、
//
// フレームタイプは「0x04」
// 5バイト目にフラグ0x01を立てます。
//------------------------------------------------------------
int FrameProcessor::sendSettingsAck(SSL *ssl){

	printf(MAZENDA_BR("\n=== Send Settings Ack === (length=0, flags=0x%02x, streamid=0)\n"), FLAGS_ACK);
	// When this bit(ACK) is set, the payload of the SETTINGS frame MUST be empty. (sec6.5)
	const unsigned char settingframeAck[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, static_cast<char>(FrameType::SETTINGS), FLAGS_ACK, 0x00, 0x00, 0x00, 0x00 };
	int writelen = BINARY_FRAME_LENGTH;
	printf(MAZENDA_BR("=== Start write SETTINGS frame ACK flags === (length=%d, flags=0x%02x, streamid=0)\n"), writelen, FLAGS_ACK);
	// MEMO: const unsigned char[9]は const_castで一気にunsigned char*へと変換できる。reinterpret_castは不要。
	if( FrameProcessor::writeFrame(ssl, const_cast<unsigned char*>(settingframeAck), writelen) < 0 ){
		// TBD: errorとclose_socketは入れる
		return -1;
	}
	return 0;
}

int FrameProcessor::sendDataFrame(SSL *ssl){
	const unsigned char dataFrame[BINARY_FRAME_LENGTH+2] = { 0x00, 0x00, 0x02 /* 2byte */, static_cast<char>(FrameType::DATA), FLAGS_END_STREAM, 0x00, 0x00, 0x00, 0x01 /* streamid */, 0x4f /* O */, 0x4b /* K */};
	printf(MAZENDA_BR("=== Start write Data Frame ==="));
	int writelen = BINARY_FRAME_LENGTH+2; // FIXME
	if( FrameProcessor::writeFrame(ssl, const_cast<unsigned char*>(dataFrame), writelen) < 0 ){
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
//		:method GET
//		:path /
//		:scheme https
//		:authority nghttp2.org
//
// 本来HTTP2はHPACKという方法で圧縮します.
// 今回は上記のHTTP2のセマンティクスを圧縮なしで記述します.
//
// 一つのヘッダフィールドの記述例
//
// |0|0|0|0|	  0|   // 最初の4ビットは圧縮に関する情報、次の4ビットはヘッダテーブルのインデクス.(今回は圧縮しないのですべて0)
// |0|			  7|   // 最初の1bitは圧縮に関する情報(今回は0)、次の7bitはフィールドの長さ
// |:method|		   // フィールドをそのままASCIIのオクテットで書く。
// |0|			  3|   // 最初の1bitは圧縮に関する情報(今回は0)、次の7bitはフィールドの長さ
// |GET|			   // 値をそのままASCIIのオクテットで書く。
//
// 上記が一つのヘッダフィールドの記述例で、ヘッダーフィールドの数だけこれを繰り返す.
//
// See: https://tools.ietf.org/html/rfc7541#appendix-B
//------------------------------------------------------------
int FrameProcessor::sendHeadersFrame(StreamState* str_state, SSL *ssl, const unsigned int &streamid, const std::map<std::string, std::string> &headers, uint8_t flags){

	std::list<std::pair<int /*length*/, unsigned char*>> pktHeaderList;    // pairの中には「パケット長、パケットへのポインタ」が含まれる
	unsigned int total = 0;
    for (const auto& [key, value] : headers){
		unsigned char* query;
		int ret_bytes;
		ret_bytes = Hpack::createHpack(key, value, query);           // Hpack表現を生成する
		pktHeaderList.push_back( std::make_pair(ret_bytes, query) ); // Hpack表現のサイズとポインタへの値をペアとしてlistに追加
		total += ret_bytes;
	}

	// フレームを生成する
	unsigned char* framepayload;
	framepayload = createFramePayload(total, static_cast<char>(FrameType::HEADERS), flags, streamid);  // 第２引数: フレームタイプはHEADER「0x01」、第３引数: END_STREAM(0x1)とEND_HEADERS(0x4)を有効にします、第４引数はstramID

	// パケット配列全体分のメモリを確保して、先で生成したフレームをコピー
	unsigned char* headersframe;
	headersframe = static_cast<unsigned char*>(std::malloc(BINARY_FRAME_LENGTH+total));
	memcpy(headersframe, framepayload, BINARY_FRAME_LENGTH);

	// フレーム分は上記でmemcpy済みなので、そこからのoffsetでmemcpyにヘッダパケット情報(Hpack)をコピーする
	int offset = BINARY_FRAME_LENGTH;
	for(auto itr = pktHeaderList.begin(); itr != pktHeaderList.end(); ++itr) {
		memcpy(headersframe+offset, itr->second, itr->first);
		offset += itr->first;
	}

	int writelen = total+BINARY_FRAME_LENGTH;
	printf(MAZENDA_BR("=== Start write HEADERS frame === (length=%d, flags=0x%02x, streamid=%d)"), writelen, flags, streamid);
	for (const auto& [key, value] : headers){
		printf(ORANGE_BR("\t%s: %s"), key.c_str(), value.c_str());
	}

	// ヘッダの送信処理
	if( FrameProcessor::writeFrame(ssl, headersframe, writelen) < 0 ){
		return -1;
	}

	str_state->setSendHeaders();

	// END_STREAMヘッダが付与されていたらフラグをセット
	if(flags & FLAGS_END_STREAM){
		str_state->setSendEndStream();
	}

	if(flags & FLAGS_END_HEADERS){
		str_state->setSendEndHeaders();
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
int FrameProcessor::sendGowayFrame(SSL *ssl, const unsigned int last_streamid, const unsigned int error_code){
	// FIXME: payloadはとりあえず固定
	printf(MAZENDA_BR("\n=== Start write GOAWAY frame === (payload_length=8, flags=0x00, streamid=0)"));
	printf(ORANGE_BR("\tlast_streamid=%d, error_code=%d"), last_streamid, error_code);

	unsigned char goawayframe[17] = { 0x00, 0x00, 0x08, static_cast<char>(FrameType::GOAWAY), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// last_streamid
	// FIXME: last_streamidは31bitなので先頭1bitが不要なのでその対応を検討するべき
	_copyUint32Into4byte(&(goawayframe[9]), last_streamid);

	// error_code
	_copyUint32Into4byte(&(goawayframe[13]), error_code);

	int writelen = sizeof(goawayframe);
	if( FrameProcessor::writeFrame(ssl, goawayframe, writelen) < 0 ){
		return -1;
	}
	return 0;
}

int FrameProcessor::sendWindowUpdateFrame(SSL *ssl, unsigned int streamid, const unsigned int increment_size){
	printf(MAZENDA_BR("\n\n=== Start write Window Update frame === (payload_length=4, flags=0x00, streamid=%d)"), streamid);
	printf(ORANGE_BR("\twindow_size_increment = %d"), increment_size);

	// 上位3byteは4byte固定(window_update仕様)、タイプは0x08、フラグなし、streamidは0x00、最後の4byteはincrement_size
	unsigned char windowUpdate[13] = { 0x00, 0x00, 0x04 , static_cast<char>(FrameType::WINDOW_UPDATE), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	_copyUint32Into4byte(&(windowUpdate[5]), streamid);        // streamidで上書き
	_copyUint32Into4byte(&(windowUpdate[9]), increment_size);  // 最後の4byteはincrement_size

	int writelen = sizeof(windowUpdate);
	if( FrameProcessor::writeFrame(ssl, windowUpdate, writelen) < 0 ){
		return -1;
	}
	return 0;
}

int FrameProcessor::sendRstStreamFrame(SSL *ssl, unsigned int &streamid, unsigned int error_code){
	printf(MAZENDA_BR("\n=== Start write RST_STREAM frame === (streamid=%d, error_code=%d"), streamid, error_code);
//	printf(ORANGE_BR("\tstreamid = %d, error_code = %d"), streamid, error_code);

	// 上位3byteは4byte固定(rst_stream仕様)、タイプは0x03、フラグは定義されていない(0x00)
	unsigned char rstStream[13] = { 0x00, 0x00, 0x04, static_cast<char>(FrameType::RST_STREAM), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	_copyUint32Into4byte(&(rstStream[5]), streamid);
	_copyUint32Into4byte(&(rstStream[9]), error_code);

	int writelen = sizeof(rstStream);
	if( FrameProcessor::writeFrame(ssl, rstStream, writelen) < 0 ){
		return -1;
	}
	return 0;
}

int FrameProcessor::writeFrame(SSL* &ssl, unsigned char* data, int &data_length){

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
					printf(RED_BR("Error Occured: Preface SSL_write"));
					return ret;
				}
		}
		if (b) break;
	}
	return ret;
}

//////////////////////////
// READ
//////////////////////////
// フレームペイロード(9byte)を読み込む関数
int FrameProcessor::readFramePayload(SSL* ssl, unsigned char* &p, unsigned int& payload_length, unsigned char* type, unsigned char* flags, unsigned int& streamid){	// TODO: unsigned intに変更した方がいいかも

	int r = 0;
	int ret = 0;
	unsigned char buf[BUF_SIZE] = { 0 }; 
	unsigned char* tmpbuf = buf; 

	while (payload_length < BINARY_FRAME_LENGTH){

		// 指定した9byteではなく、1byteしか取得できずにSSL_ERROR_NONEに入るケースが存在するのでサイズチェックが必要
		tmpbuf = buf;
		r = SSL_read(ssl, tmpbuf, BINARY_FRAME_LENGTH);
//		printf(ORANGE_BR("%%%%% BINARY_FRAME: %02x %02x %02x %02x %02x %02x %02x %02x %02x, READ_BYTES=%d"), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], r);
		ret = SSL_get_error(ssl, r); 
		memcpy(p + payload_length, tmpbuf, r);	  // 読み込んだサイズ分だけコピーする
		switch (ret){
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_WANT_READ:
				continue;
			default:
				if (r == -1){
					printf(RED_BR("Error Occured: HEADER_FRAME SSL_read. error code=%d"), ret);
					return ret;  // TODO: 後で綺麗にする
				}
		}
		payload_length += r;
	}
	
	if( payload_length != 9 ){
		printf(RED_BR("[ERROR] TOTAL BYTE NOTE MATCH 9"));
	}

	_to_framedata3byte(p, payload_length);
	_to_frametype(p, type);
	_to_frameflags(p, flags);
	_to_framestreamid(p, streamid);
//	printf(ORANGE_BR("payload_length= %d, streamid = %d"), payload_length, streamid);

	return ret;
}


// 一部の小さなフレーム用のデータでは、取得したコンテンツを解析して使います。このためのデータを取得します。
// 大きなデータはreadFrameContentsで読み込んでください。
int FrameProcessor::getFrameContentsIntoBuffer(SSL* ssl, unsigned int payload_length, unsigned char* p){

	int r = 0;
	int ret = 0;
	unsigned char buf[BUF_SIZE] = { 0 };
	unsigned char* tmpbuf = buf;
	unsigned int total_read_bytes = 0;

	while (payload_length > 0){

		tmpbuf = buf;
		r = SSL_read(ssl, tmpbuf, payload_length);
		ret = SSL_get_error(ssl, r);
		memcpy(p + total_read_bytes, tmpbuf, r);	  // 読み込んだサイズ分だけコピーする
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
int FrameProcessor::readFrameContents(SSL* ssl, unsigned int &payload_length, int print){

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
					printf(RED_BR("Error Occured: payload contents SSL_read"));
					return ret;
				}
		}

		payload_length -= r;

//		printf(ORANGE_BR("Rest payload_length = %d"), payload_length);
		if(print) printf("%s", p);
	}
	return ret;
}

void FrameProcessor::_copy2byteIntoUint16(unsigned char *p, uint16_t &dst){
	dst = ((p[0] & 0xFF) << 8 ) + (p[1] & 0xFF);
}

void FrameProcessor::_copy4byteIntoUint32(unsigned char *p, unsigned int &dst){
	dst = ( (p[0] & 0xFF) << 24 ) + ((p[1] & 0xFF) << 16 ) + ((p[2] & 0xFF) << 8 ) + ((p[3] & 0xFF) );
}

void FrameProcessor::_copyUint16Into2byte(unsigned char *p, const uint16_t &src){
	p[0] = (src >> 8) & 0xff;
	p[1] = src & 0xff;
	return;
}

void FrameProcessor::_copyUint32Into4byte(unsigned char *p, const unsigned int &src){
	p[0] = (src >> 24) & 0xff;
	p[1] = (src >> 16) & 0xff;
	p[2] = (src >> 8) & 0xff;
	p[3] = src & 0xff;
	return;
}

// フレーム長3byteを取得してunsigned intにコピーする
unsigned char* FrameProcessor::_to_framedata3byte(unsigned char * &p, unsigned int &n){
//	printf(ORANGE_BR("_to_framedata3byte: %02x %02x %02x"), p[0], p[1], p[2]);
	u_char buf[4] = {0};	  // bufを4byte初期化
	memcpy(&(buf[1]), p, 3);  // bufの2byte目から4byteめまでをコピー
	memcpy(&n, buf, 4);		  // buf領域を全てコピー
	n = ntohl(n);			  // ネットワークバイトオーダーを変換
	p += 3;					  // 読み込んだ3byteをスキップする		// MEMO: 引数を&で参照にしないとポインタの加算が行われない。
	return p;
}

// パケットからフレームタイプを取得する
void FrameProcessor::_to_frametype(unsigned char * &p, unsigned char *type){
//	printf(ORANGE_BR("_to_frametype: %02x"), p[0]);
	*type = p[0];
	p++;
}

// パケットからフレームタイプのflagsを取得する
void FrameProcessor::_to_frameflags(unsigned char * &p, unsigned char *flags){	// _to_frametypeと共通
//	printf(ORANGE_BR("_to_frameflags: %02x"), p[0]);
	*flags = p[0];
	p++;
}

// パケットからstreamidを取得する
void FrameProcessor::_to_framestreamid(unsigned char * &p, unsigned int& streamid){
	streamid = 0;
	// see: How to make int from char[4]? (in C)
	//	 https://stackoverflow.com/questions/17602229/how-to-make-int-from-char4-in-c/17602505
//	printf("_to_framestreamid: %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3]);
	streamid = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3]);
	p += 4;
}
