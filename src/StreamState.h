#pragma once

#include<string>
#include<map>

enum Http2State {
	idle = 0,
	open,
	local_half_closed,
	remote_half_closed,
	local_reserved,
	remote_reserved,
	closed
};

class StreamState {
private:

//	// streamid
	const unsigned int streamid_;
//
//	// request pseudo-header (defined in sec8.1.2.3)
//	std::string method_;
//	std::string scheme_;
//	std::string authority_;
//	std::string path_;

//	// response pseudo-header (defined in sec8.1.2.4)
//	std::string status_;
//
//	// request & response headers
//	std::map<std::string, std::string> request_headers_;
//	std::map<std::string, std::string> response_headers_;
//
//	// flags related StreamState
//	bool sendPP_;    // PP: PUSH_PROMISE
//	bool recvPP_;
	bool sendH_;     // H: HEADER
	bool recvH_;
	bool sendEH_;    // EH: END_HEADER flags
	bool recvEH_;
	bool sendES_;    // ES: END_STREAM flags
	bool recvES_;
	bool sendRS_;    // RS: RST_SRREAM flags
	bool recvRS_;

//
//	// state
//	Http2State state;
//
	unsigned int consumer_data_bytes_;
	unsigned int peer_consumer_data_bytes_;
	unsigned char* header_buffer_;
	unsigned int header_buffer_size_;

public:
	StreamState(unsigned int streamid);
	unsigned int getStreamId() const;
	void setSendHeaders();
	bool getSendHeaders() const;
	void setRecieveHeaders();
	bool getRecieveHeaders() const;
	void setSendEndHeaders();
	bool getSendEndHeaders() const;
	void setRecieveEndHeaders();
	bool getRecieveEndHeaders() const;
	void setSendEndStream();
	bool getSendEndStream() const;
	void setRecieveEndStream();
	bool getRecieveEndStream() const;
	void setSendRstStream();
	bool getSendRstStream() const;
	void setRecieveRstStream();
	bool getRecieveRstStream() const;

	void reset_peer_consumer_data_bytes();
	unsigned int get_peer_consumer_data_bytes() const;
	bool setHeaderBuffer(const unsigned char* buf, const unsigned int payload_length);
	unsigned char* getHeaderBuffer() const;
	unsigned int getHeaderBufferSize() const;
	bool incrementPeerPayloadAndCheckWindowUpdateIsNeeded(const unsigned int &payload_length);
	bool checkPeerHeadersRecieved() const;

}; 
