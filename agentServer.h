#pragma once
#include <functional>
#include <unordered_map>
#include "server_logic.h"
#include <url_error_code.h>
#include <url_fetcher.h>
class NodeManager;
class AgentServer;
class AgentDnsUserData;
class TargetSession;

#define CUSTOM_MESSAGE_DNS_RESULT 101

struct AgentTimer
{
	void* _param;
	NetHandle _session_handle;
	platform_timer_t _timer_handle;
	AgentServer* _server;
	bool _loop;
};



struct ServerConfig
{
	uint16_t _http_port = 8887;
	uint16_t _agent_port = 7777;
	uint32_t _io_thread_count = 1;
	uint32_t _worker_thread_count = 1;
	std::string _report_ip = "127.0.0.1";

	uint32_t _connect_timeout = 30000;
	uint32_t _idle_timeout = 60000;

	std::string _api_key = "f485d7f678cf7b8d2b51ca38d4d37280";

	std::string _upload_ip = "221.131.165.131";

	uint32_t _upload_port = 8383;

	uint32_t _upload_duration = 10000;
	std::string _download_url = "http://221.131.165.131:18907/test.bak";
};

class UrlFetcher;
class AgentSession;

class AgentServer : public ServerLogic
{
public:
	AgentServer();
	~AgentServer();

	virtual bool is_agent()
	{
		return true;
	}

	virtual bool is_need_split()
	{
		return true;
	}
	virtual std::string get_server_http_ip()
	{
		return "0.0.0.0";
	}
	virtual uint16_t get_server_http_port()
	{
		return _server_config._http_port;
	}

	virtual std::string get_server_ip()
	{
		return std::string();
	}

	virtual uint16_t get_server_port()
	{
		return _server_config._agent_port;
	}

	virtual uint32_t  get_worker_thread_count() 
	{ 
		return 1; 
	}

	virtual uint32_t get_send_buffer_size()
	{ 
		return 1024 * 1024 * 5; 
	}

	virtual uint32_t get_recv_buffer_size() 
	{ 
		return 1024 * 1024; 
	}

	virtual void OnPreInit();
	virtual void OnAccept(NetHandle h, const session_info_t& data, void* pNetThreadData)override;
	virtual void OnConnected(NetHandle h, const session_info_t& data, void* pNetThreadData)override;
	virtual void OnClose(NetHandle h, const session_info_t& data, void* pNetThreadData)override;
	virtual int process_message(NetHandle handle, const char* msg, uint32_t msg_size, void* pNetThreadData) override;
	virtual int process_custom_message(uint64_t param, const char* msg, uint32_t msg_size, void* pNetThreadData) override;
	virtual void OnHttpAgentData(NetHandle handle, const char* data, uint32_t size, void* pNetThreadData);
	virtual void OnHttpHeader(NetHandle handle, const std::string& location, struct HttpContent* content, void* pNetThreadData);

public:
	platform_timer_t CreateTimer(NetHandle sessionHandle, int32_t duration, void* param, bool loop);
	bool ReleaseTimer(platform_timer_t timerHandle);


	ServerConfig& GetServerConfig()
	{
		return _server_config;
	}

	void CloseTarget(NetHandle h);
	void _connect_target(const std::string& target_server, uint32_t target_port, AgentSession* session);
private:
	

	virtual void OnTimer(platform_timer_t timerHandle, void* param);
private:
	void _private_api(NetHandle handle, struct HttpContent* content);

	void _load_config();
	void _dns_result(AgentDnsUserData* usrdata);
private:
	std::unordered_map<platform_timer_t, AgentTimer*> _session_timer_map;

	ServerConfig _server_config;
	NodeManager* _node_manager = nullptr;

	std::unordered_map<NetHandle, AgentSession*> _session_map;

	std::unordered_map<NetHandle, TargetSession*> _target_map;
	NetSession* _http_agent_session = nullptr;

	std::string _dummy;


	std::string _msg_data;
};