#include "StreamState.h"
#include <stdlib.h>
#include <cstring>

StreamState::StreamState(unsigned int streamid): streamid_(streamid), sendPP_(false), recvPP_(false), sendH_(false), recvH_(false), sendEH_(false), recvEH_(false), sendES_(false), recvES_(false), sendRS_(false), recvRS_(false), current_state_(Http2State::idle), consumer_data_bytes_(0), peer_consumer_data_bytes_(0), header_buffer_(nullptr), header_buffer_size_(0) {
	printf("streamid init %d, %d\n", streamid, streamid_);
	printf("this in constructor: %p\n", this);
}

unsigned int StreamState::getStreamId() const { 
	printf("this in getStreamId: %p\n", this);
	printf("getStreamId = %d\n", streamid_);
	return streamid_;
}

// FIXME:: elseのERROR出力はあとで削除する予定
void StreamState::setSendHeaders() { 
	if(current_state_ == Http2State::idle){
		printf("\nsetSendHeaders: State Changed From idle into open. streamid=%d\n", streamid_);
		current_state_ = Http2State::open;
	} else if (current_state_ == Http2State::local_reserved){
		current_state_ = Http2State::remote_half_closed;
		printf("\nsetSendHeaders: State Changed From local_reserved into remote_half_closed. streamid=%d\n", streamid_);
	} else {
		printf("\n[ERROR] setSendHeaders. current_state_ = %d, streamid=%d\n", current_state_, streamid_);
		return;
	}
	sendH_ = true;
}

bool StreamState::getSendHeaders() const { 
	return sendH_;
}

void StreamState::setRecieveHeaders() { 
	if(current_state_ == Http2State::idle){
		current_state_ = Http2State::open;
		printf("\nsetRecieveHeaders: State Changed From idle into open. streamid=%d\n", streamid_);
	} else if (current_state_ == Http2State::remote_reserved){
		current_state_ = Http2State::local_half_closed;
		printf("\nsetRecieveHeaders: State Changed From remote_reserved into local_half_closed. streamid=%d\n", streamid_);
	} else {
		printf("\n[ERROR] setRecieveHeaders. current_state_ = %d, streamid=%d\n", current_state_, streamid_);
		return;
	}
	recvH_ = true;
}

bool StreamState::getRecieveHeaders() const { 
	return recvH_;
}

void StreamState::setSendEndHeaders() { 
// 判定は不要?
	sendEH_ = true;
}

bool StreamState::getSendEndHeaders() const { 
	return sendEH_;
}

void StreamState::setRecieveEndHeaders() { 
	recvEH_ = true;
}

bool StreamState::getRecieveEndHeaders() const { 
	return recvEH_;
}

void StreamState::setSendEndStream() { 
	if(current_state_ == Http2State::open){
		printf("\nsetSendEndStream: State Changed From open into local_half_closed. streamid=%d\n", streamid_);
		current_state_ = Http2State::local_half_closed;
	} else if(current_state_ == Http2State::remote_half_closed){
		printf("\nsetSendEndStream: State Changed From remote_half_closed into closed. streamid=%d\n", streamid_);
		current_state_ = Http2State::closed;
	} else {
		printf("\n[ERROR] setSendEndStream. current_state_ = %d, streamid=%d\n", current_state_, streamid_);
		return;
	}
	sendES_ = true;
}

bool StreamState::getSendEndStream() const { 
	return sendES_;
}

void StreamState::setRecieveEndStream() { 
	if(current_state_ == Http2State::open){
		printf("\nsetRecieveEndStream: State Changed From open into local_half_closed. streamid=%d\n", streamid_);
		current_state_ = Http2State::remote_half_closed;
	} else if(current_state_ == Http2State::local_half_closed){
		printf("\nState Changed From local_half_closed into closed. streamid_=%d\n", streamid_);
		current_state_ = Http2State::closed;
	} else {
		printf("\n[ERROR] setRecieveEndStream. current_state_ = %d. streamid_=%d\n", current_state_, streamid_);
		return;
	}
	recvES_ = true;
}

bool StreamState::getRecieveEndStream() const { 
	return recvES_;
}

void StreamState::setSendRstStream() { 

	if(current_state_ == Http2State::open || current_state_ == Http2State::local_half_closed || current_state_ == Http2State::remote_half_closed || current_state_ == Http2State::local_reserved || current_state_ == Http2State::remote_reserved){
		printf("\nsetSendRstStream: State Changed into closed. current_state_ = %d, streamid=%d\n", current_state_, streamid_);
		current_state_ = Http2State::closed;
		sendRS_ = true;
	} else {
		printf("\n[ERROR] setSendRstStream. current_state_ = %d, streamid=%d\n", current_state_, streamid_);
	}
}

bool StreamState::getSendRstStream() const { 
	return sendRS_;
}

void StreamState::setRecieveRstStream() {
	if(current_state_ == Http2State::open || current_state_ == Http2State::local_half_closed || current_state_ == Http2State::remote_half_closed || current_state_ == Http2State::local_reserved || current_state_ == Http2State::remote_reserved){
		printf("\nsetRecieveRstStream: State Changed into closed. current_state_ = %d, streamid=%d\n", current_state_, streamid_);
		current_state_ = Http2State::closed;
		recvRS_ = true;
	} else {
		printf("\n[ERROR] setRecieveRstStream. current_state_ = %d, streamid=%d\n", current_state_, streamid_);
	}
}

bool StreamState::getRecieveRstStream() const {
	return recvRS_;
}

void StreamState::reset_peer_consumer_data_bytes() { 
	peer_consumer_data_bytes_ = 0;
}

unsigned int StreamState::get_consumer_data_bytes() const {
	return consumer_data_bytes_;
}

unsigned int StreamState::get_peer_consumer_data_bytes() const {
	return peer_consumer_data_bytes_;
}

bool StreamState::setHeaderBuffer(const unsigned char* buf, const unsigned int payload_length){
	if(header_buffer_ == nullptr){
		// malloc
//		printf("malloc start payload_length = %d\n", payload_length);
		header_buffer_ = static_cast<unsigned char*>(malloc(payload_length));
		memcpy(header_buffer_, buf, payload_length);
		header_buffer_size_ = payload_length;
	} else {
		// realloc
		if( header_buffer_size_ + payload_length > 2147483647 ){  // FIXME: とりあえずint最大
			return false;
		}

//		printf("realloc start , header_buffer_size_=%d, payload_length=%d, total=%d\n", header_buffer_size_, payload_length, header_buffer_size_+payload_length);
		// realloc はtmpに格納してNULL判定してから、header_buffer_に戻すのが一般的らしい
		unsigned char *tmp;
		if( (tmp = static_cast<unsigned char*>(realloc(header_buffer_, header_buffer_size_+payload_length))) == nullptr ){
			return false;
		}
		header_buffer_ = tmp;
		memcpy(&(header_buffer_[header_buffer_size_]), buf, payload_length);
		header_buffer_size_ += payload_length;
	}
	return true;
}

unsigned char* StreamState::getHeaderBuffer() const {
	return header_buffer_;
}

unsigned int StreamState::getHeaderBufferSize() const {
	return header_buffer_size_;
}

bool StreamState::incrementPeerPayloadAndCheckWindowUpdateIsNeeded(const unsigned int &payload_length){
	peer_consumer_data_bytes_ += payload_length;
	if( peer_consumer_data_bytes_ > 30000 ){  // FIXME
		return true;
	}
	return false;
}

// HEADERSフレームおよびCONTINUATIONフレームの受信が完了したことを示す
bool StreamState::checkPeerHeadersRecieved() const {
//	printf("recvEH_ = %d, recvES_ = %d\n", recvEH_, recvES_);
	if( recvEH_ == true && recvES_ == true ){
		return true;
	}
	return false;
}


Http2State StreamState::getStreamStatus() const{
	return current_state_; 
}

//// 戻り値ではステータスを取得し、ステータス変更も行う
//// See: sec5.1 Stream States
////   https://tools.ietf.org/html/rfc7540#section-5.1
//Http2State StreamState::changeAndGetStatus(){
//
//	switch(current_state_){
//		case Http2State::idle:
//			if(sendH_ || recvH_) {
//				current_state_ = Http2State::open;
//			} else if(sendPP_) {
//				 current_state_ = Http2State::local_reserved;
//			} else if(recvPP_) {
//				 current_state_ = Http2State::remote_reserved;
//			}
//			break;
//		case Http2State::open:
//			if(recvES_){
//				current_state_ = Http2State::remote_half_closed;
//			} else if(sendES_) {
//				 current_state_ = Http2State::local_half_closed;
//			}
//			break;
//		case Http2State::local_half_closed:
//			if(recvES_ || sendRS_ || recvRS_){
//				current_state_ = Http2State::closed;
//			}
//			break;
//		case Http2State::remote_half_closed:
//			if(sendES_ || sendRS_ || recvRS_){
//				current_state_ = Http2State::closed;
//			}
//			break;
//		case Http2State::local_reserved:
//			if(sendRS_ || recvRS_){
//				current_state_ = Http2State::closed;
//			} else if(sendH_){
//				current_state_ = Http2State::remote_half_closed;
//			}
//			break;
//		case Http2State::remote_reserved:
//			if(sendRS_ || recvRS_){
//				current_state_ = Http2State::closed;
//			} else if(recvH_){
//				current_state_ = Http2State::local_half_closed;
//			}
//			break;
//		case Http2State::closed:
//			/* do nothing from this state */
//			break;
//	}
//
//	return current_state_;
//}
