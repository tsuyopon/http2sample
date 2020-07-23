#pragma once

#include <map>
#include "FrameProcessor.h"

// コネクションに関連するデータを管理するクラス
// (host, port)ペア毎に1つ生成される。
class ConnectionState {
public:
	ConnectionState();
	void set_send_initial_frames();

	// my settings
	void set_header_table_size_(unsigned int table_size);
	void set_max_concurrent_streams(unsigned int concurrent);
	void set_initial_window_size(unsigned int window_size);
	void set_max_frame_size(unsigned int frame_size);
	void set_max_header_list_size(unsigned int header_list_size);
	void getSettingsMap(std::map<uint16_t, uint32_t> &setmap);

	// peer settings
	void peer_set_header_table_size_(unsigned int table_size);
	void peer_set_max_concurrent_streams(unsigned int concurrent);
	void peer_set_initial_window_size(unsigned int window_size);
	void peer_set_max_frame_size(unsigned int frame_size);
	void peer_set_max_header_list_size(unsigned int header_list_size);
	void peer_getSettingsMap(std::map<uint16_t, uint32_t> &setmap);

private:
	/* manage*/
	bool send_initial_frames_;
	unsigned int total_consume_data_;       /* for flow control total data read */
	unsigned int max_create_stream_id_;
	unsigned int concurrent_num;

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

}; 
