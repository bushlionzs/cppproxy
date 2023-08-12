#include "agentSession.h"
#include "http_util.h"
#include "url.h"
#include <platform_log.h>
#include <net_factory.h>
#include "net_header.h"
#include "string_util.h"
#include "base64.h"
#include <assert.h>
#include "net_manager.h"
#include "platform_socket.h"
#include "agentServer.h"
#include "time_util.h"

#include <mutex>

AgentSession::AgentSession(
	NetHandle h,
    AgentServer* server)
{
	_session_handle = h;
	_server = server;
	_cache_data.reserve(1024);

	_usr_connected_time = get_tick_count();

	_last_data_time = platform_get_tickcount();
	_data_timer = _server->CreateTimer(h, 5000, nullptr, true);
}

AgentSession::~AgentSession()
{
	if (_connect_timer != INVALID_TIMER_ID)
	{
		_server->ReleaseTimer(_connect_timer);
		_connect_timer = INVALID_TIMER_ID;
	}

	if (_data_timer != INVALID_TIMER_ID)
	{
		_server->ReleaseTimer(_data_timer);
		_data_timer = INVALID_TIMER_ID;
	}
}

void AgentSession::Close()
{
	NetFactory::GetInstance()->CloseNetHandle(_session_handle);
}

void AgentSession::OnClose(const session_info_t& data)
{
	NOTICE_LOG("[usr_handle:%llu]user onclose", _session_handle);

	STAT_LOG("%s:%d|%s:%d|%d|%s|%s|%s|%s:%d|%s|%s|%v|%llums|%llu|%llu|%d|%s",
		data.peer_ip, data.peer_port,  //usr ip:port
		data.local_ip, data.local_port,  //server ip:port
		0,   //authtype
		_username.c_str(),//username
		_username.c_str(),
		"http",
		_target_server.c_str(), _target_port,
		_target_ip.c_str(),
		"",
		get_tick_count() - _usr_connected_time,
		_recv_bytes,
		_send_bytes,
		0,
		""
	);

	if (_target_handle != INVALID_NET_HANDLE)
	{
		_server->CloseTarget(_target_handle);
	}
	

}

void AgentSession::ProcessHttpHeader(const std::string& location, struct HttpContent* content)
{
	int errcode;
	
	if (content->method == HTTP_METHOD_CONNECT)
	{
		string_view host;
		if (!util::split_host_port(location, &host, &_target_port))
		{
			errcode = 451;
			goto error;

		}

		_target_server = host.to_string();


		
	}
	else
	{
		string_view schema, hostport, uri;
		if (!util::parse_url(location, &schema, &hostport, &uri))
		{
			errcode = 451;
			goto error;
		}
		string_view host;
		if (!util::split_host_port(hostport, &host, &_target_port))
		{
			errcode = 451;
			goto error;
		}

		_target_server = host.to_string();

		_cache_data.clear();
		_cache_data += content->methodstring;
		_cache_data += " /";
		_cache_data += uri.to_string();
		_cache_data += " ";
		_cache_data += content->proto;
		_cache_data += "\r\n";

		for (auto& obj : content->headers)
		{
			if (obj.first == "Proxy-Connection")
				continue;
			if (obj.first == "Proxy-Authorization")
			{
				_authentication = obj.second;
				continue;
			}

			if (obj.first == "Kdl-Tps-Channel")
			{
				_usr_channel = atoi(obj.second.c_str());
				continue;
			}

			_cache_data += obj.first;
			_cache_data += ": ";
			_cache_data += obj.second;
			_cache_data += "\r\n";
		}
		_cache_data += "\r\n";
	}


	_server->_connect_target(_target_server, _target_port, this);
	
	return;
error:
	_handle_error_response(errcode);
}


void AgentSession::ProcessAgentDataToUser(const char* data, uint32_t size)
{
	_recv_bytes += size;
	int32_t ret = NetFactory::GetInstance()->SendData(_session_handle, (const uint8_t*)data, size);

	if (ret != 0)
	{
		WARNING_LOG("[usrhandle:%llu,target_handle:%llu,size:%d,ret:%d]send TransportData to user", _session_handle, _target_handle, size, ret);
	}
	else
	{
		NOTICE_LOG("[usr_handle:%llu,target_handle:%llu,size:%d]send TransportData to user", _session_handle, _target_handle, size);
	}
}

void AgentSession::ProcessDataToTarget(const char* data, uint32_t size)
{
	_send_bytes += size;
	int32_t ret = NetFactory::GetInstance()->SendData(_target_handle, (const uint8_t*)data, size);

	if (ret != 0)
	{
		WARNING_LOG("[usr_handle:%llu, target_handle:%llu,size:%d, ret:%d]send TransportData to user", _session_handle, _target_handle, size, ret);
	}
	else
	{
		NOTICE_LOG("[usr_handle:%llu, target_handle:%llu,size:%d]send TransportData to user", _session_handle, _target_handle, size);
	}

}

void AgentSession::ProcessTimeout(platform_timer_t id, void* param)
{
	if (id == _connect_timer)
	{
		NOTICE_LOG("[handle:%llu, target:%s:%d]this session is timeout when connecting to target",
			_session_handle, _target_server.c_str(), _target_port);
		_handle_error_response(503);
	}
	else if (id == _data_timer)
	{
		uint64_t current = platform_get_tickcount();
		if (current - _last_data_time > _server->GetServerConfig()._idle_timeout)
		{
			NOTICE_LOG("[handle:%llu, timeout value:%d,current:%llu, last:%llu]this session will be closed because idle timeout",
				_session_handle, _server->GetServerConfig()._idle_timeout, current, _last_data_time);
			Close();
		}
	}
}

void AgentSession::ProcessDnsFailed()
{
	_handle_error_response(449);
}

void AgentSession::ProcessTargetClose()
{
	if (_recv_bytes > 0)
	{
		WARNING_LOG("[usr_handle:%llu, target_handle:%llu, _recv_bytes:%llu]target server disconnected", 
			_session_handle, _target_handle, _recv_bytes);
		_target_handle = INVALID_NET_HANDLE;
		Close();
	}
	else
	{
		_handle_error_response(449);
	}
}

void AgentSession::ProcessTargetConnected(NetHandle h)
{
	_target_handle = h;
	static std::string connectResponse = "HTTP/1.1 200 Connection Established\r\n\r\n";

	int32_t ret = NetFactory::GetInstance()->SendData(_session_handle, (const uint8_t*)connectResponse.data(), connectResponse.size());

	if (ret != 0)
	{
		WARNING_LOG("[usr_handle:%llu, target_handle:%llu, ret:%d]send Connection failed", _session_handle, h, ret);
	}

	
}

uint64_t AgentSession::_allocChannel()
{
	static uint64_t channel_id = 1;

	static std::mutex mutex;

	uint64_t id = 0;
	std::lock_guard<std::mutex> lock(mutex);
	id = channel_id++;
	return id;
}


void AgentSession::_handle_error_response(
	uint32_t code)
{
	static std::map<uint32_t, std::string> code_map = {
		{440, "Bandwidth Over Limit"},
		{441, "Request Rate Over Limit"},
		{442, "Authentication Type Error"},
		{443, "Foreign Client Forbidden"},
		{444, "Download Not Allowed"},
		{445, "Illegal Request Forbidden"},
		{446, "Host DNS Failed"},
		{447, "Real-name Authentication Required"},
		{448, "Target Port Forbidden"},
		{449, "Foreign Host Forbidden"},
		{450, "IP As Host Forbidden"},
		{451, "Miss Host"},
		{452, "Public Host Required"},
		{453, "Proxy Port Error"},
		{454, "Proxy Authentication Expired"},
		{455, "Risk Host Forbidden"},
		{503, "Connect Timeout"},
		{504, "Lack of Resource"}
	};

	auto itor = code_map.find(code);
	if (itor != code_map.end())
	{
		std::string response = str_format("HTTP/1.1 %d %s\r\nConnection: close\r\nServer: kdl/1.0.0\r\nContent-Length:0\r\n\r\n",
			code, itor->second.c_str());
		int32_t ret = NetFactory::GetInstance()->SendData(_session_handle, (const uint8_t*)response.data(), response.size());

		
		WARNING_LOG("[usr_handle:%llu, code:%d, server:%s,ret:%d]_handle_error_response failed", _session_handle, code, _target_server.c_str(), ret);
		
	}
	else
	{
		assert(false);
	}

}

bool AgentSession::_parseUsername(const std::string& authentication, std::string& username)
{
	username.clear();

	auto pos = authentication.find_first_of(" ");
	if (pos != 5)
	{
		return false;
	}

	const char* data = authentication.c_str() + pos + 1;
	uint32_t size = authentication.size() - pos - 1;

	try
	{
		Base64Decrypt decrypt(data, size);

		username = decrypt.PlainText();

		pos = username.find_last_of(":");
		if (pos == std::string::npos)
		{
			return false;
		}

		username.erase(pos);
	}
	catch (...)
	{
		return false;
	}

	return true;
}


void AgentSession::_set_bandwidth_limiter(uint64_t bandwidth)
{
	
}




