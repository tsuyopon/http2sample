#include "ConnectionState.h"

// Note: 構造体かクラスどちらで管理するか再考してもいいかも

ConnectionState::ConnectionState(){

	send_initial_frames_ = false;

	// initial value is defined in RFC7540 sec6.5
	header_table_size_ = 4096;
	enable_push_ = 1;
	max_concurrent_streams_ = 100;
	initial_window_size_ = 65535;
	max_frame_size_ = 16384;
	max_header_list_size_ = 16384;  // The initial value of this setting is unlimited.

	// peer settings
	peer_header_table_size_ = 4096;
	peer_enable_push_ = 1;
	peer_max_concurrent_streams_ = 100;
	peer_initial_window_size_ = 65535;
	peer_max_frame_size_ = 16384;
	peer_max_header_list_size_ = 16384;  // The initial value of this setting is unlimited.

}

void ConnectionState::set_send_initial_frames(){
	send_initial_frames_ = true;
}

void ConnectionState::set_header_table_size_(unsigned int table_size){
	header_table_size_ = table_size;
}

void ConnectionState::set_max_concurrent_streams(unsigned int concurrent){
	max_concurrent_streams_ = concurrent;
}

void ConnectionState::set_initial_window_size(unsigned int window_size){
	initial_window_size_ = window_size;
}

void ConnectionState::set_max_frame_size(unsigned int frame_size){
	max_frame_size_ = frame_size;
}

void ConnectionState::set_max_header_list_size(unsigned int header_list_size){
	max_header_list_size_ = header_list_size;
}

void ConnectionState::peer_set_header_table_size_(unsigned int table_size){
	peer_header_table_size_ = table_size;
}

void ConnectionState::peer_set_max_concurrent_streams(unsigned int concurrent){
	peer_max_concurrent_streams_ = concurrent;
}

void ConnectionState::peer_set_initial_window_size(unsigned int window_size){
	peer_initial_window_size_ = window_size;
}

void ConnectionState::peer_set_max_frame_size(unsigned int frame_size){
	peer_max_frame_size_ = frame_size;
}

void ConnectionState::peer_set_max_header_list_size(unsigned int header_list_size){
	peer_max_header_list_size_ = header_list_size;
}

void ConnectionState::getSettingsMap(std::map<uint16_t, uint32_t> &setmap){
	// FIXME: デフォルト値と異なる場合のみ本来送付すればOK
	setmap[SettingsId::SETTINGS_HEADER_TABLE_SIZE] = header_table_size_;
	setmap[SettingsId::SETTINGS_ENABLE_PUSH] = enable_push_;
	setmap[SettingsId::SETTINGS_MAX_CONCURRENT_STREAMS] = max_concurrent_streams_;
	setmap[SettingsId::SETTINGS_INITIAL_WINDOW_SIZE] = initial_window_size_;
	setmap[SettingsId::SETTINGS_MAX_FRAME_SIZE] = max_frame_size_;
	setmap[SettingsId::SETTINGS_MAX_HEADER_LIST_SIZE] = header_table_size_;
}
