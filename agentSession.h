#pragma once
#include <unordered_map>
#include "net_handle.h"
#include "http_defines.h"
#include "platform_util.h"
#include "rate_limiter.h"
#include "server_def.h"

class NodeManager;
class Node;
class AgentServer;

struct AgentDnsUserData
{
	AgentServer* _agent;
	NetHandle _handle;
	std::string _domain;
	uint16_t _port;
	std::vector<std::string> _ip_list;
	int32_t _dns_err;
};

class AgentSession
{
public:
	AgentSession(NetHandle h, AgentServer* server);
	~AgentSession();

	void Close();
	void OnClose(const session_info_t& data);
	void ProcessHttpHeader(const std::string& location, struct HttpContent* content);
	void ProcessAgentDataToUser(const char* data, uint32_t size);
	void ProcessDataToTarget(const char* data, uint32_t size);
	void ProcessTimeout(platform_timer_t id, void* param);

	void ProcessDnsFailed();

	void ProcessTargetClose();

	void ProcessTargetConnected(NetHandle h);

	NetHandle getNetHandle()
	{
		return _session_handle;
	}

private:
	uint64_t _allocChannel();
	void _handle_error_response(
		uint32_t code);

	bool _parseUsername(const std::string& authentication, std::string& username);

	void _set_bandwidth_limiter(uint64_t bandwidth);

	
private:
	AgentServer* _server;
	NetHandle _session_handle = INVALID_NET_HANDLE;
	NetHandle _target_handle= INVALID_NET_HANDLE;
	
	std::string _target_server;
	uint16_t _target_port = 0;
	std::string _target_ip;
	uint64_t _usr_channel = 0;
	uint64_t _agent_channel = 0;

	uint64_t _usr_connected_time = 0;
	std::string _cache_data;
	std::string _msg_data;

	bool _connectd = false;

	platform_timer_t _connect_timer = INVALID_TIMER_ID;
	platform_timer_t  _data_timer = INVALID_TIMER_ID;
	uint64_t _last_data_time = 0;
	std::string _authentication;
	std::string _username;

	uint64_t _recv_bytes = 0;
	uint64_t _send_bytes = 0;

};