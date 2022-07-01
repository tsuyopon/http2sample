#include "StreamState.h"
#include "ConnectionState.h"

ConnectionState::ConnectionState(bool isServer): manage_streamid_(0), is_server_(isServer)  {

	// FIXME: 初期化子リストへあとで変更する
	send_initial_frames_ = false;
	first_settings_frame_ = false;
	max_create_streamid_ = 0;
	concurrent_num_ = 0;

	// initial value is defined in RFC7540 sec6.5
	/******************************************
	* local settings
	******************************************/
	header_table_size_ = 4096;
	enable_push_ = 1;
	max_concurrent_streams_ = 100;
	initial_window_size_ = 65535;
	max_frame_size_ = 16384;
	max_header_list_size_ = 16384;  // The initial value of this setting is unlimited.

	/******************************************
	* peer settings
	******************************************/
	// peer settings
	peer_header_table_size_ = 4096;
	peer_enable_push_ = 1;
	peer_max_concurrent_streams_ = 100;
	peer_initial_window_size_ = 65535;
	peer_max_frame_size_ = 16384;
	peer_max_header_list_size_ = 16384;  // The initial value of this setting is unlimited.

	/******************************************
	* for flow control settings
	******************************************/
	consumer_data_bytes_ = 0;
	peer_consumer_data_bytes_ = 0;

}

void ConnectionState::set_send_initial_frames(){
	send_initial_frames_ = true;
}

unsigned int ConnectionState::get_concurrent_num() const {
	return concurrent_num_;
}

unsigned int ConnectionState::get_manage_streamid() const {
	return manage_streamid_;
}

void ConnectionState::set_first_settings_frame() {
	first_settings_frame_ = true;
}

bool ConnectionState::get_first_settings_frame() const {
	return first_settings_frame_;
}

bool ConnectionState::get_is_server() const {
	return is_server_;
}

// FIXME: 非同期時にはロックが必要
unsigned int ConnectionState::get_next_streamid() {
	if( max_create_streamid_ == 0 ){
		if(is_server_){
			max_create_streamid_ = 2;
		} else {
			max_create_streamid_ = 1;
		}
	} else {
		max_create_streamid_ += 2;
	}
	return max_create_streamid_;
}

/******************************************
* local settings
******************************************/
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

/******************************************
* peer settings
******************************************/
void ConnectionState::set_peer_header_table_size_(unsigned int table_size){
	peer_header_table_size_ = table_size;
}

void ConnectionState::set_peer_max_concurrent_streams(unsigned int concurrent){
	peer_max_concurrent_streams_ = concurrent;
}

void ConnectionState::set_peer_initial_window_size(unsigned int window_size){
	peer_initial_window_size_ = window_size;
}

void ConnectionState::set_peer_max_frame_size(unsigned int frame_size){
	peer_max_frame_size_ = frame_size;
}

void ConnectionState::set_peer_max_header_list_size(unsigned int header_list_size){
	peer_max_header_list_size_ = header_list_size;
}

void ConnectionState::getSettingsMap(std::map<uint16_t, uint32_t> &setmap){
	// FIXME: デフォルト値と異なる場合のみ本来送付すればOK
	setmap[SettingsId::SETTINGS_HEADER_TABLE_SIZE] = header_table_size_;
	setmap[SettingsId::SETTINGS_ENABLE_PUSH] = 0;
	//setmap[SettingsId::SETTINGS_ENABLE_PUSH] = enable_push_; // FIXME: デフォルトは1(nginxでのリクエストで失敗するので一時的に0に変更した)
	setmap[SettingsId::SETTINGS_MAX_CONCURRENT_STREAMS] = max_concurrent_streams_;
	setmap[SettingsId::SETTINGS_INITIAL_WINDOW_SIZE] = initial_window_size_;
	setmap[SettingsId::SETTINGS_MAX_FRAME_SIZE] = max_frame_size_;
	setmap[SettingsId::SETTINGS_MAX_HEADER_LIST_SIZE] = header_table_size_;
}

void ConnectionState::reset_peer_consumer_data_bytes() {
	peer_consumer_data_bytes_ = 0;
}

unsigned int ConnectionState::get_peer_consumer_data_bytes() const {
	return peer_consumer_data_bytes_;
}

// 通信相手に対してWINDOW_UPDATEが必要かどうかを判定します。
// このアルゴリズムはRFC7540では規定されていません。
// この関数はDATAフレームの場合にしか呼び出してはいけません
bool ConnectionState::incrementPeerPayloadAndCheckWindowUpdateIsNeeded(const unsigned int &payload_length){
	peer_consumer_data_bytes_ += payload_length;
	if( peer_consumer_data_bytes_ >  50000 ){  // FIXME
		return true;
	}
	return false;
}

// ConnectionStateからStreamStateインスタンス生成を管理する
bool ConnectionState::createStream(StreamState* &str_state) {
	// TODO: MAC_CONNCURRENTを超過していたらfalseを返す
	// idはget_next_streamid()を使って自動的にインクリメント
	// 管理用プールに登録する
	// 実行中のストリーム数をインクリメントする
	// StreamStateインスタンスを返却する

	// FIXME: 31bitなのでintの方が適切かも(全体に影響するので後回し)
	unsigned int streamid;
	streamid = get_next_streamid();
//	printf("streamid = %d\n", streamid);
	str_state  = new StreamState(streamid);  // FIXME: deleteかけ
	stream_pool_[streamid] = str_state;
	concurrent_num_++;
//	printf("createStream addr=%p\n", stream_pool_[streamid]);
	return true;
}

bool ConnectionState::createStreamById(unsigned int streamid, StreamState* &str_state) {

	// FIXME: 31bitなのでintの方が適切かも(全体に影響するので後回し)
//	printf("streamid = %d\n", streamid);
	str_state  = new StreamState(streamid);  // FIXME: deleteかけ
	stream_pool_[streamid] = str_state;
	concurrent_num_++;
//	printf("createStream addr=%p\n", stream_pool_[streamid]);
	return true;
}


// フレーム受信したらstreamidからStreamStateインスタンスを取得する。
bool ConnectionState::findStreamByStreamId(unsigned int streamid, StreamState* &str_stream) {

	// streamid=0はStreamStateを持たないのでfalseを応答する
	if( streamid == 0 ){
		return false;
	}

	// TODO:存在しないstreamidも扱う必要がある

	// streamidからStreamStateインスタンスを返却する
	str_stream = stream_pool_[streamid];
	printf("streamid=%d, get addr=%p\n", streamid, str_stream);
	return true;
}

void ConnectionState::deleteStream(unsigned int streamid){
	// DELETEを追加する
	stream_pool_.erase(streamid);   // FIXME* streamidのチェック 
	concurrent_num_--;
}
