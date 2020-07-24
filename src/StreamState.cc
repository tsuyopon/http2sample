#include "StreamState.h"

StreamState::StreamState(): sendH_(false), recvH_(false), consumer_data_bytes_(0), peer_consumer_data_bytes_(0) {}

void StreamState::setSendHeaders() { 
	sendH_ = true;
}

bool StreamState::getSendHeaders() const { 
	return sendH_;
}

void StreamState::setRecieveHeaders() { 
	recvH_ = true;
}

bool StreamState::setRecieveHeaders() const { 
	return recvH_;
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
