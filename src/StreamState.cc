#include "StreamState.h"
#include <stdlib.h>

StreamState::StreamState(): sendH_(false), recvH_(false), sendEH_(false), recvEH_(false), sendES_(false), recvES_(false), sendRS_(false), recvRS_(false), consumer_data_bytes_(0), peer_consumer_data_bytes_(0), header_buffer_(nullptr), header_buffer_size_(0) {}

void StreamState::setSendHeaders() { 
	sendH_ = true;
}

bool StreamState::getSendHeaders() const { 
	return sendH_;
}

void StreamState::setRecieveHeaders() { 
	recvH_ = true;
}

bool StreamState::getRecieveHeaders() const { 
	return recvH_;
}

void StreamState::setSendEndHeaders() { 
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
	sendES_ = true;
}

bool StreamState::getSendEndStream() const { 
	return sendES_;
}

void StreamState::setRecieveEndStream() { 
	recvES_ = true;
}

bool StreamState::getRecieveEndStream() const { 
	return recvES_;
}

void StreamState::setSendRstStream() { 
	sendRS_ = true;
}

bool StreamState::getSendRstStream() const { 
	return sendRS_;
}

void StreamState::setRecieveRstStream() {
	recvRS_ = true;
}

bool StreamState::getRecieveRstStream() const {
	return recvRS_;
}

void StreamState::reset_peer_consumer_data_bytes() { 
	peer_consumer_data_bytes_ = 0;
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
	printf("recvEH_ = %d, recvES_ = %d\n", recvEH_, recvES_);
	if( recvEH_ == true && recvES_ == true ){
		return true;
	}
	return false;
}
