#include "StreamState.h"

StreamState::StreamState(): sendH_(false), recvH_(false), sendEH_(false), recvEH_(false), sendES_(false), recvES_(false), sendRS_(false), recvRS_(false), consumer_data_bytes_(0), peer_consumer_data_bytes_(0) {}

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

bool StreamState::incrementPeerPayloadAndCheckWindowUpdateIsNeeded(const unsigned int &payload_length){
	peer_consumer_data_bytes_ += payload_length;
	if( peer_consumer_data_bytes_ > 30000 ){  // FIXME
		return true;
	}
	return false;
}
