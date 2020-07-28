#pragma once

#include <map>
#include "FrameProcessor.h"

// コネクションに関連するデータを管理するクラス
// (host, port)ペア毎に1つ生成される。
class ConnectionState {
public:
	ConnectionState(bool isServer);

	// manage
	void set_send_initial_frames();
	unsigned int get_manage_streamid() const;
	bool get_is_server() const;
	unsigned int get_next_streamid();

	// my settings
	void set_header_table_size_(unsigned int table_size);
	void set_max_concurrent_streams(unsigned int concurrent);
	void set_initial_window_size(unsigned int window_size);
	void set_max_frame_size(unsigned int frame_size);
	void set_max_header_list_size(unsigned int header_list_size);
	void getSettingsMap(std::map<uint16_t, uint32_t> &setmap);

	// peer settings
	void set_peer_header_table_size_(unsigned int table_size);
	void set_peer_max_concurrent_streams(unsigned int concurrent);
	void set_peer_initial_window_size(unsigned int window_size);
	void set_peer_max_frame_size(unsigned int frame_size);
	void set_peer_max_header_list_size(unsigned int header_list_size);
	void peer_getSettingsMap(std::map<uint16_t, uint32_t> &setmap);

	void reset_peer_consumer_data_bytes();
	unsigned int get_peer_consumer_data_bytes() const;
	bool incrementPeerPayloadAndCheckWindowUpdateIsNeeded(const unsigned int &payload_length);

private:
	/* manage*/
	const unsigned int manage_streamid_;
	bool is_server_;  // FIXME: あとでenumへ変更
	bool send_initial_frames_;
	unsigned int max_create_streamid_;
	unsigned int concurrent_num_;

	/* settings */
	unsigned int header_table_size_;
	unsigned int enable_push_;
	unsigned int max_concurrent_streams_;
	unsigned int initial_window_size_;
	unsigned int max_frame_size_;
	unsigned int max_header_list_size_;

	/* settings peer */
	unsigned int peer_header_table_size_;
	unsigned int peer_enable_push_;
	unsigned int peer_max_concurrent_streams_;
	unsigned int peer_initial_window_size_;
	unsigned int peer_max_frame_size_;
	unsigned int peer_max_header_list_size_;

	/* flow control */
	unsigned int consumer_data_bytes_;
	unsigned int peer_consumer_data_bytes_;

}; 
