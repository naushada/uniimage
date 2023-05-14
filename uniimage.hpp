#ifndef __uniimage__hpp__
#define __uniimage__hpp__

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <clocale>
#include <cmath>
#include <cstring>

#include <vector>
#include <iostream>
#include <fstream>
#include <memory>
#include <thread>
#include <sstream>
#include <unordered_map>
#include <tuple>
#include <getopt.h>
#include <atomic>


#include "ace/Reactor.h"
#include "ace/Basic_Types.h"
#include "ace/Event_Handler.h"
#include "ace/Task.h"
#include "ace/INET_Addr.h"
#include "ace/SOCK_Stream.h"
#include "ace/SOCK_Acceptor.h"
#include "ace/Task_T.h"
#include "ace/Timer_Queue_T.h"
#include "ace/Reactor.h"
#include "ace/OS_Memory.h"
#include "ace/Thread_Manager.h"
#include "ace/Get_Opt.h"
#include "ace/Signal.h"
#include "ace/SSL/SSL_SOCK.h"
#include "ace/SSL/SSL_SOCK_Stream.h"
#include "ace/SSL/SSL_SOCK_Connector.h"
#include "ace/Semaphore.h"

#if 0
#include <bsoncxx/json.hpp>
#include <bsoncxx/types.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/array.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/string/to_string.hpp>
#endif

#include "http.hpp"

std::uint32_t from_json_array_to_map(const std::string json_obj, std::unordered_map<std::string, std::string>& out);
std::uint32_t from_json_element_to_string(const std::string json_obj, const std::string key, std::string& str_out);

namespace noor {
    class Uniimage;
    class NetInterface;
    class CommonResponse;

    struct response {
        std::uint16_t type;
        std::uint16_t command;
        std::uint16_t messages_id;
    };
};

class noor::Uniimage {
    public:
        //EMP (Embedded Micro Protocol) parser
        enum EMP_COMMAND_TYPE : std::uint16_t {
           Request = 0,
           Command_OR_Notification = 1,
           Response = 2,
        };
        enum EMP_COMMAND_ID : std::uint16_t {
           RegisterGetVariable     = 104,          /**< Register to get notified immediately and when a path or sub path changes. */
           RegisterVariable        = 105,          /**< Register to get notified when a path or sub path changes. */
           UnregisterVariable      = 106,          /**< Unregister a previously registered notification. */
           NotifyVariable          = 107,          /**< Notify a change in the monitored values. */
           ExecVariable            = 108,          /**< Execute a node. */
           RegisterExec            = 109,          /**< Register to get notified when a path is executed. */
           NotifyExec              = 110,          /**< Notify that a path is executed. */
           GetVariable             = 113,          /**< Recursively get values in a single request. */
           SingleGetVariable       = 114,          /**< Get a single path value. */
           SetVariable             = 115,          /**< Set one or more values. */
           ListVariable            = 116,          /**< List direct children of a branch path. */
           NotifyFd                = 200,          /**< Notify file descriptor passing. */
        };

        struct emp_t {
            emp_t() : m_type(0), m_command(0), m_message_id(0), m_response("") {}
            ~emp_t() {}
            std::uint16_t m_type;
            std::uint16_t m_command;
            std::uint16_t m_message_id;
            std::string m_response;
        };

        enum client_connection: std::uint16_t {
            Disconnected = 0,
            Inprogress,
            Connected
        };

        Uniimage(auto config) {
            m_config = std::move(config);
            tcp_client_fd(-1);
            uds_client_fd(-1);
            udp_client_fd(-1);
            
           do {
               if(!m_config["role"].compare("server")) {
                   //start tcp server 
                   if(!m_config["protocol"].compare("tcp")) {
                       tcp_server(m_config["server-ip"], std::stoi(m_config["server-port"]));
                   }
                   else if(!m_config["protocol"].compare("udp")) {
                       udp_server(m_config["server-ip"], std::stoi(m_config["server-port"]));
                   }
                   web_server(m_config["server-ip"], std::stoi(m_config["web-port"]));
                   break;
               }
               m_is_reg_ds = false;
               std::int32_t channel = -1;
               /* Set up the address we're going to bind to. */
               bzero(&m_uds_server, sizeof(m_uds_server));
               m_sock_name = "/var/run/treemgr/treemgr.sock";
               m_uds_server.sun_family = PF_UNIX;
               strncpy(m_uds_server.sun_path, m_sock_name.c_str(), sizeof(m_uds_server.sun_path) -1);
               std::size_t len = sizeof(struct sockaddr_un);

               channel = ::socket(PF_UNIX, SOCK_STREAM/*|SOCK_NONBLOCK*/, 0);
               if(channel < 0) {
                   std::cout << "line: "<<__LINE__ << "Creation of Unix socket Failed" << std::endl;
                   break;
               }

               uds_client_fd(channel);
               uds_client(client_connection::Disconnected);
               /* set the reuse address flag so we don't get errors when restarting */
               auto flag = 1;
               if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
                   std::cout << "line: " << __LINE__ << "Error: Could not set reuse address option on unix socket!" << std::endl;
                   break;
               }

               auto rc = ::connect(channel, reinterpret_cast< struct sockaddr *>(&m_uds_server), len);
               if(rc == -1) {
                   std::cout << __FILE__ <<":"<<__LINE__ <<"Connect is failed errno: "<< std::strerror(errno) << std::endl;
                   break;
               }
               uds_client(client_connection::Connected);
               
               if(!m_config["protocol"].compare("tcp")) {
                    //TCP Client
                    create_and_connect_tcp_socket(m_config["server-ip"], std::stoi(m_config["server-port"]));
               }
               else if(!m_config["protocol"].compare("udp")) {
                    udp_client(m_config["server-ip"], std::stoi(m_config["server-port"]));
               }
           } while(0);
        }

        ~Uniimage() {
            close(uds_client_fd());
            close(tcp_client_fd());
            m_ds_request_list.clear();
            m_client_list.clear();
            tcp_client(client_connection::Disconnected);
            uds_client(client_connection::Disconnected);

        }

        emp_t uds_rx(std::int32_t channel);
        std::string tcp_rx(std::int32_t channel);
        std::string web_rx(std::int32_t channel);
        
        std::int32_t uds_tx(std::int32_t channel, const std::string& data);
        std::int32_t tcp_tx(std::int32_t channel, const std::string& data);
        std::int32_t web_tx(std::int32_t channel, const std::string& data);
        std::string serialise(noor::Uniimage::EMP_COMMAND_TYPE type, noor::Uniimage::EMP_COMMAND_ID cmd, const std::string& data);
        std::string packArguments(const std::string& prefix, std::vector<std::string> fields = {}, std::vector<std::string> filter = {});
        std::int32_t registerGetVariable(const std::string& prefix, std::vector<std::string> fields = {}, std::vector<std::string> filter = {});
        std::int32_t getVariable(const std::string& prefix, std::vector<std::string> fields = {}, std::vector<std::string> filter = {});
        std::int32_t getSingleVariable(const std::string& prefix);
        std::string build_web_response(Http& http);
        std::int32_t create_and_connect_tcp_socket(const std::string& IP, std::uint16_t port);
        std::int32_t udp_server(const std::string& IP, std::uint16_t port);
        std::int32_t udp_client(const std::string& IP, std::uint16_t port);
        std::int32_t udp_tx(std::int32_t channel, const std::string& data);
        std::string udp_rx(std::int32_t channel);

        std::int32_t udp_client_fd() const {
            return(m_udp_client_fd);
        }

        void udp_client_fd(std::int32_t channel) {
            m_udp_client_fd = channel;
        }
        
        std::int32_t udp_server_fd() const {
            return(m_udp_server_fd);
        }

        void udp_server_fd(std::int32_t channel) {
            m_udp_server_fd = channel;
        }

        void uds_client_fd(std::int32_t channel) {
            m_uds_client_fd = channel;
        }

        void tcp_client_fd(std::int32_t channel) {
            m_tcp_client_fd = channel;
        }

        void web_server_fd(std::int32_t channel) {
            m_web_server_fd = channel;
        }
        std::int32_t uds_client_fd() const {
            return(m_uds_client_fd);
        }

        std::int32_t tcp_client_fd() const {
            return(m_tcp_client_fd);
        }
        std::int32_t web_server_fd() const {
            return(m_web_server_fd);
        }

        void tcp_server_fd(std::int32_t channel) {
            m_tcp_server_fd = channel;
        }

        std::int32_t tcp_server_fd() const {
            return(m_tcp_server_fd);
        }

        client_connection uds_client() {
            return(m_client_list[uds_client_fd()]); 
        }

        void uds_client(client_connection status) {
            m_client_list[uds_client_fd()] = status;
        }

        client_connection tcp_client() {
            return(m_client_list[tcp_client_fd()]); 
        }

        void tcp_client(client_connection status) {
            m_client_list[tcp_client_fd()] = status;
        }
        std::int32_t start_client();
        std::int32_t start_server();
        std::int32_t tcp_server(const std::string& IP, std::uint16_t PORT);
        std::int32_t web_server(const std::string& IP, std::uint16_t PORT);
        void add_element(std::uint16_t type, std::uint16_t cmd, std::uint16_t msg_id, std::string prefiex, std::string rsp="default");

    private:
        std::int32_t m_uds_client_fd;
        std::string m_sock_name;
        struct sockaddr_un m_uds_server;
        std::int32_t m_tcp_client_fd;
        std::int32_t m_tcp_server_fd;
        std::uint16_t m_tcp_server_port;
        struct sockaddr_in m_server_addr;
        std::atomic<std::uint16_t> m_message_id;
        //type, command, message_id, prefix and response for a tuple
        std::vector<std::tuple<std::uint16_t, std::uint16_t, std::uint16_t, std::string, std::string>> m_ds_request_list;
        std::unordered_map<std::int32_t, client_connection> m_client_list;
        bool m_is_reg_ds;
        //Webserver 
        std::uint16_t m_web_server_fd;
        std::uint16_t m_web_server_port;
        struct sockaddr_in m_web_server;
        //std::tuple<message_id, prefix, response>
        std::tuple<std::uint16_t, std::string, std::string> m_ds_response;
        std::unordered_map<std::string, std::string> m_config;
        std::int32_t m_udp_client_fd;
        std::int32_t m_udp_server_fd;
        struct sockaddr_in m_self_addr;
};

class noor::CommonResponse {
    public:
        
        ~CommonResponse() = default;

        static noor::CommonResponse& instance() {
            static noor::CommonResponse m_inst;
            return(m_inst);
        }

        auto response(std::int32_t fd) {
            return(m_responses[fd]);
        }

        void response(std::int32_t fd, std::string rsp) {
            m_responses[fd].push_back(rsp);
        }
        auto& response() {
            return(m_responses);
        }

    private:
        CommonResponse() = default;
        std::unordered_map<std::int32_t, std::vector<std::string>> m_responses;
};

class noor::NetInterface {
    public:
        //EMP (Embedded Micro Protocol) parser
        enum EMP_COMMAND_TYPE : std::uint16_t {
           Request = 0,
           Command_OR_Notification = 1,
           Response = 2,
        };
        enum EMP_COMMAND_ID : std::uint16_t {
           RegisterGetVariable     = 104,          /**< Register to get notified immediately and when a path or sub path changes. */
           RegisterVariable        = 105,          /**< Register to get notified when a path or sub path changes. */
           UnregisterVariable      = 106,          /**< Unregister a previously registered notification. */
           NotifyVariable          = 107,          /**< Notify a change in the monitored values. */
           ExecVariable            = 108,          /**< Execute a node. */
           RegisterExec            = 109,          /**< Register to get notified when a path is executed. */
           NotifyExec              = 110,          /**< Notify that a path is executed. */
           GetVariable             = 113,          /**< Recursively get values in a single request. */
           SingleGetVariable       = 114,          /**< Get a single path value. */
           SetVariable             = 115,          /**< Set one or more values. */
           ListVariable            = 116,          /**< List direct children of a branch path. */
           NotifyFd                = 200,          /**< Notify file descriptor passing. */
        };

        struct emp {
            emp() : m_type(0), m_command(0), m_message_id(0), m_response_length(0), m_response("") {}
            ~emp() {}
            std::uint16_t m_type;
            std::uint16_t m_command;
            std::uint16_t m_message_id;
            std::uint32_t m_response_length;
            std::string m_response;
        };

        enum client_connection: std::uint16_t {
            Disconnected = 0,
            Inprogress,
            Connected
        };

        enum cache_element: std::uint32_t {
            CMD_TYPE = 0,
            CMD = 1,
            MESSAGE_ID = 2,
            PREFIX = 3,
            RESPONSE = 4
        };

        enum service_type: std::uint32_t {
            UNIX = 0,

            TCP_CONSOLE_APP_CONSUMER_SVC_ASYNC = 1,
            TCP_DS_APP_CONSUMER_SVC_ASYNC = 2,

            // TCP Server for DS
            TCP_CONSOLE_APP_PROVIDER_SVC = 3,
            TCP_DS_APP_PROVIDER_SVC = 4,
            
            TCP_CONSOLE_APP_PEER_CONNECTED_SVC = 5,
            TCP_DS_APP_PEER_CONNECTED_SVC = 6,
            // TCP Server for Console

            // Web Server
            TCP_WEB_APP_PROVIDER_SVC = 7,
            TCP_WEB_APP_PEER_CONNECTED_SVC = 8,
        };

        NetInterface() {
            m_is_register_variable = false; 
            m_handle = -1; 
            m_message_id = 0; 
            m_response_cache.clear();
            m_connected_clients.clear();
            m_web_connections.clear();
            m_tcp_connections.clear();

        }
        NetInterface(std::unordered_map<std::string, std::string> config) {
            if(config.empty()) {
                std::cout << "line: " << __LINE__ << " config is empty" << std::endl;
            }
            m_config = config;
            m_is_register_variable = false; 
            m_handle = -1; 
            m_message_id = 0; 
            m_response_cache.clear();
            m_connected_clients.clear();
            m_web_connections.clear();
            m_tcp_connections.clear();
        }
        virtual ~NetInterface() {}
        void close();
        std::int32_t tcp_client(const std::string& IP, std::uint16_t PORT, bool isAsync=false);
        std::int32_t tcp_client_async(const std::string& IP, std::uint16_t PORT);
        std::int32_t udp_client(const std::string& IP, std::uint16_t PORT);
        std::int32_t uds_client(const std::string& PATH="/var/run/treemgr/treemgr.sock");
        std::int32_t tcp_server(const std::string& IP, std::uint16_t PORT);
        std::int32_t udp_server(const std::string& IP, std::uint16_t PORT);
        std::int32_t web_server(const std::string& IP, std::uint16_t PORT);
        std::int32_t start_client(std::uint32_t timeout_in_ms, std::vector<std::tuple<std::unique_ptr<NetInterface>, service_type>>);
        std::int32_t start_server(std::uint32_t timeout_in_ms, std::vector<std::tuple<std::unique_ptr<NetInterface>, service_type>>);
        std::int32_t tcp_rx(std::string& data);
        std::int32_t tcp_rx(std::int32_t channel, std::string& data);
        std::int32_t tcp_rx(std::int32_t channel, std::string& data, service_type svcType);
        emp uds_rx();
        std::int32_t web_rx(std::string& data);
        std::int32_t web_rx(std::int32_t fd, std::string& data);
        std::int32_t web_tx(std::int32_t channel, const std::string& req);
        std::int32_t udp_rx(std::string& data);
        
        std::int32_t web_tx(const std::string& data);
        std::int32_t udp_tx(const std::string& data);
        std::int32_t uds_tx(const std::string& data);
        std::int32_t tcp_tx(const std::string& data);
        std::int32_t tcp_tx(std::int32_t channel, const std::string& data);
        std::string serialise(noor::Uniimage::EMP_COMMAND_TYPE cmd_type, noor::Uniimage::EMP_COMMAND_ID cmd, const std::string& req);
        std::string packArguments(const std::string& prefix, std::vector<std::string> fields = {}, std::vector<std::string> filter = {});
        std::int32_t registerGetVariable(const std::string& prefix, std::vector<std::string> fields = {}, std::vector<std::string> filter = {});
        std::int32_t getSingleVariable(const std::string& prefix);
        std::int32_t getVariable(const std::string& prefix, std::vector<std::string> fields = {}, std::vector<std::string> filter = {});
        std::string build_web_response(Http& http);
        std::string process_web_request(const std::string& req);
        std::string handleGetMethod(Http& http);
        std::string buildHttpResponse(Http& http, const std::string& rsp_body);
        std::string handleOptionsMethod(Http& http);
        std::string buildHttpRedirectResponse(Http& http, std::string rsp_body = "");
        std::string buildHttpResponseOK(Http& http, std::string body, std::string contentType);
        std::string get_contentType(std::string ext);

        virtual std::string onReceive(std::string in) {
            std::cout << "line: " << __LINE__ << "Must be overriden " << std::endl;
            return(std::string());
        }

        virtual std::int32_t onClose(std::string in) {
            std::cout << "line: " << __LINE__ << "Must be overriden " << std::endl;
            return(-1);
        }


        void ip(std::string IP) {
            m_ip = IP;
        }
        std::string ip() const {
            return(m_ip);
        }
        void port(std::uint16_t _p) {
            m_port = _p;
        }
        std::uint16_t port() const {
          return(m_port);
        }
        std::int32_t handle() const {
            return(m_handle);
        }

        void handle(std::int32_t fd) {
            m_handle = fd;
        }

        std::string uds_socket_name() const {
            return(m_uds_socket_name);
        }

        void uds_socket_name(std::string uds_name) {
            m_uds_socket_name = uds_name;
        }

        auto& response_cache() {
            return(m_response_cache);
        }
        void add_element_to_cache(std::tuple<std::uint16_t, std::uint16_t, std::uint16_t, std::string, std::string> elm) {
            m_response_cache.push_back(elm);
        }

        void update_response_to_cache(std::int32_t id, std::string rsp) {
            auto it = std::find_if(m_response_cache.begin(), m_response_cache.end(), [&](auto& inst) {
                if(std::get<cache_element::MESSAGE_ID>(inst) == id) {
                    return(true);
                }
                return(false);
            });

	        if(it != m_response_cache.end()) {
                std::get<cache_element::RESPONSE>(*it).assign(rsp);
	        }
        }

        void connected_client(client_connection st) {
            //m_connected_clients.insert(std::make_pair(handle(), st));
            m_connected_clients[handle()] = st;
        }

        auto& connected_client() {
            return(m_connected_clients);
        }

        auto connected_client(std::int32_t channel) {
            return(m_connected_clients[channel]);
        }

        auto& web_connections() {
            return(m_web_connections);
        }

        auto& tcp_connections() {
            return(m_tcp_connections);
        }

        auto& unix_connections() {
            return(m_unix_connections);
        }

        auto& inet_server() {
            return(m_inet_server);
        }

        auto& inet_peer() {
            return(m_inet_peer);
        }

        auto& un_server() {
            return(m_un_server);
        }
        
        std::unordered_map<std::string, std::string> get_config() const {
            return(m_config);
        }

        void set_config(std::unordered_map<std::string, std::string> cfg) {
            m_config = cfg;
        }

        bool is_register_variable() const {
            return(m_is_register_variable);
        }
        void is_register_variable(bool yes) {
            m_is_register_variable = yes;
        }

        std::atomic<std::uint16_t>& message_id() {
            return(m_message_id);
        }

    private:
        std::atomic<std::uint16_t> m_message_id;
        bool m_is_register_variable;
        std::string m_uds_socket_name;
        std::string m_ip;
        std::uint16_t m_port;
        //file descriptor
        std::int32_t m_handle;
        //INET socket address
        struct sockaddr_in m_inet_server;
        struct sockaddr_in m_inet_peer;
        // UNIX socket address 
        struct sockaddr_un m_un_server;
        //type, command, message_id, prefix and response for a tuple
        std::vector<std::tuple<std::uint16_t, std::uint16_t, std::uint16_t, std::string, std::string>> m_response_cache;
        std::unordered_map<std::int32_t, client_connection> m_connected_clients;
        //key = fd, Value = <fd, IP, PORT, service_type, DestIP, RxBytes, TxBytes, timestamp>
        std::unordered_map<std::int32_t, std::tuple<std::int32_t, std::string, std::int32_t, service_type, std::string, std::int32_t, std::int32_t, std::int32_t>> m_web_connections;
        std::unordered_map<std::int32_t, std::tuple<std::int32_t, std::string, std::int32_t, service_type, std::string, std::int32_t, std::int32_t, std::int32_t>> m_tcp_connections;
        std::unordered_map<std::int32_t, std::tuple<std::int32_t, std::string, std::int32_t, service_type, std::string, std::int32_t, std::int32_t, std::int32_t>> m_unix_connections;
        std::unordered_map<std::string, std::string> m_config;

};

class TcpClient: public noor::NetInterface {
    public:
        TcpClient(auto cfg, auto svcType): NetInterface(cfg) {
            if(svcType == noor::NetInterface::service_type::TCP_CONSOLE_APP_CONSUMER_SVC_ASYNC) {
                tcp_client_async(get_config().at("server-ip"), 65344);
                std::cout << "line: " << __LINE__ << "handle: " << handle() << " console app client_connected: " << connected_client(handle()) << std::endl;    
            } else {
                tcp_client_async(get_config().at("server-ip"), std::stoi(get_config().at("server-port")));
                std::cout << "line: " << __LINE__ << "handle: " << handle() << " ds app client_connected: " << connected_client(handle()) << std::endl;
            }
        }
        ~TcpClient() {}
        virtual std::string onReceive(std::string in) override;
        virtual std::int32_t onClose(std::string in) override;
};


class UnixClient: public noor::NetInterface {
    public:
        UnixClient(): NetInterface() {
            uds_client();
        }
        ~UnixClient() {

        }
        virtual std::string onReceive(std::string in) override;
        virtual std::int32_t onClose(std::string in) override;
};


class UdpClient: public noor::NetInterface {
    public:
        UdpClient(auto config): NetInterface(config) {
            udp_client(get_config().at("server-ip"), std::stoi(get_config().at("server-port")));
        }
        ~UdpClient() {

        }
        virtual std::string onReceive(std::string in) override;
        virtual std::int32_t onClose(std::string in) override;
};


class TcpServer: public noor::NetInterface {
    public:
        TcpServer(auto config, auto svcType) : NetInterface(config) {

            std::string sIP("127.0.0.1");
            auto it = std::find_if(get_config().begin(), get_config().end(), [] (const auto& ent) {return(!ent.first.compare("server-ip"));});

            if(it != get_config().end()) {
                sIP.assign(it->second);
            }

            if(noor::NetInterface::service_type::TCP_CONSOLE_APP_PROVIDER_SVC == svcType) {
                tcp_server(sIP, 65344);    
            } else {
                tcp_server(sIP, std::stoi(get_config().at("server-port")));
            }
        }

        ~TcpServer() {}
        virtual std::string onReceive(std::string in) override;
        virtual std::int32_t onClose(std::string in) override;
};


class UdpServer: public noor::NetInterface {
    public:
        UdpServer(auto config) : NetInterface(config) {
            udp_server(get_config().at("server-ip"), std::stoi(get_config().at("server-port")));
        }
        ~UdpServer() {}
        virtual std::string onReceive(std::string in) override;
        virtual std::int32_t onClose(std::string in) override;
};


class WebServer: public noor::NetInterface {
    public:
        WebServer(auto config, service_type svcType) : NetInterface(config) {

            std::string sIP("127.0.0.1");
            auto it = std::find_if(get_config().begin(), get_config().end(), [] (const auto& ent) {return(!ent.first.compare("server-ip"));});

            if(it != get_config().end()) {
                sIP.assign(it->second);
            }
            if(svcType == noor::NetInterface::TCP_WEB_APP_PROVIDER_SVC) {
                web_server(sIP, std::stoi(get_config().at("web-port")));
            }
        }
        ~WebServer() {}

        virtual std::string onReceive(std::string in) override;
        virtual std::int32_t onClose(std::string in) override;
};


class UnixServer: public noor::NetInterface {
    public:
        UnixServer() : NetInterface() {}
        ~UnixServer() {}
        virtual std::string onReceive(std::string in) override;
        virtual std::int32_t onClose(std::string in) override;
};

#if 0
class MicroServices : public ACE_Task<ACE_MT_SYNCH> {
    public:

        int svc(void) override;
        int open(void *args=0) override;
        int close(u_long flags=0) override;

        ACE_INT32 handle_signal(int signum, siginfo_t *s, ucontext_t *u) override;

        MicroServices(ACE_Thread_Manager *thrMgr);
        virtual ~MicroServices();
};

class DatastoreConnectionHandler : public ACE_Event_Handler {
    public:
        DatastoreConnectionHandler(const std::unordered_map<std::string, std::string>& config);
        DatastoreConnectionHandler();
        virtual ~DatastoreConnectionHandler();

        ACE_INT32 handle_timeout(const ACE_Time_Value &tv, const void *act=0) override;
        ACE_INT32 handle_input(ACE_HANDLE handle) override;
        ACE_INT32 handle_signal(int signum, siginfo_t *s = 0, ucontext_t *u = 0) override;
        ACE_INT32 handle_close (ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = 0) override;
        ACE_HANDLE get_handle() const override;
    private:
        ACE_SOCK_Stream m_stream;
        ACE_INET_Addr m_listen;
        ACE_SOCK_Acceptor m_server;
        std::shared_ptr<WebConnectionHandler> m_webConn;
};

class ConsoleConnectionHandler : public ACE_Event_Handler {
    public:
        ConsoleConnectionHandler(const std::unordered_map<std::string, std::string>& config);
        ConsoleConnectionHandler();
        virtual ~ConsoleConnectionHandler();
    
        ACE_INT32 handle_timeout(const ACE_Time_Value &tv, const void *act=0) override;
        ACE_INT32 handle_input(ACE_HANDLE handle) override;
        ACE_INT32 handle_signal(int signum, siginfo_t *s = 0, ucontext_t *u = 0) override;
        ACE_INT32 handle_close (ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = 0) override;
        ACE_HANDLE get_handle() const override;
    private:
        ACE_SOCK_Stream m_stream;
        ACE_INET_Addr m_listen;
        ACE_SOCK_Acceptor m_server;
        std::shared_ptr<WebConnectionHandler> m_webConn;

};

class WebConnectionHandler : public ACE_Event_Handler {
    public:
        WebConnectionHandler(const std::unordered_map<std::string, std::string>& config);
        WebConnectionHandler();
        virtual ~WebConnectionHandler();
    
        ACE_INT32 handle_timeout(const ACE_Time_Value &tv, const void *act=0) override;
        ACE_INT32 handle_input(ACE_HANDLE handle) override;
        ACE_INT32 handle_signal(int signum, siginfo_t *s = 0, ucontext_t *u = 0) override;
        ACE_INT32 handle_close (ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = 0) override;
        ACE_HANDLE get_handle() const override;
    private:
        ACE_SOCK_Stream m_stream;
        ACE_INET_Addr m_listen;
        ACE_SOCK_Acceptor m_server;
        std::shared_ptr<DatastoreConnectionHandler> m_dsConn;
        std::shared_ptr<ConsoleConnectionHandler> m_consoleConn;

};

#endif

enum service : std::uint32_t {
    // DS Client Unix
    SERVICE_DS_UNIX = 1,
    // DS TCP Client
    SERVICE_DS_TCP = 2,
    //Shell listener on TCP
    SERVICE_SHELL_TCP = 3,
    SERVICE_WEB = 4
};

class CommonHandler {
    public:

        struct emp_t {
            emp_t() : m_type(0), m_command(0), m_message_id(0), m_response("") {}
            ~emp_t() {}
            std::uint16_t m_type;
            std::uint16_t m_command;
            std::uint16_t m_message_id;
            std::string m_response;
        };

        ~CommonHandler() {}

        static std::shared_ptr<CommonHandler> instance() {
            if(nullptr == m_instance) {
                m_instance = std::make_shared<CommonHandler>();
            }
            return(m_instance);
        }

        ACE_INT32 web_rx(ACE_HANDLE fd, std::string& data);
        ACE_INT32 tcp_rx(ACE_HANDLE fd, std::string& data);
        ACE_INT32 unix_rx(ACE_HANDLE fd, std::string& data);
        ACE_INT32 shell_rx(ACE_HANDLE fd, std::string& data);

    private:
        CommonHandler() : m_instance(nullptr) {}
        
        static std:shared_ptr<CommonHandler> m_instance;
};

class ConnectedServices : public ACE_Event_Handler {
    public:

        ConnectedServices(ACE_HANDLE handle, ACE_INET_Addr peerAddr, service svcType):
                           m_address(peerAddr),
                           m_svcType(svcType),
                           m_ip(),
                           m_handle(handle) {}

        virtual ~ConnectedServices();
        ACE_INT32 handle_input(ACE_HANDLE handle) override;

    private:
        ACE_INET_Addr m_address;
        service m_svcType;
        std::string m_ip;
        ACE_HANDLE m_handle;
};

class ServiceHandler : public ACE_Event_Handler {
    public:

        ACE_INT32 complete(ACE_SOCK_Stream &new_stream, ACE_Addr *remote_sap=0, const ACE_Time_Value *timeout=0) override;
        ACE_INT32 handle_timeout(const ACE_Time_Value &tv, const void *act=0) override;
        ACE_INT32 handle_input(ACE_HANDLE handle) override;
        ACE_INT32 handle_signal(int signum, siginfo_t *s = 0, ucontext_t *u = 0) override;
        ACE_INT32 handle_close (ACE_HANDLE = ACE_INVALID_HANDLE, ACE_Reactor_Mask = 0) override;
 

        ServiceHandler() : m_acceptors(), m_connectors(), m_config(), m_connectedServices() {}
        virtual ~ServiceHandler() = default;

        void createConnectorServices(const std::vector<std::tuple<std::string, std::uint16_t, service>>& services) {

            for(const auto& [IP, PORT, serviceType]: services) {

                std::string addr;
                addr.clear();
                if(serviceType == SERVICE_DS_UNIX) {
                    ACE_UNIX_Addr connector;
                    connector.set("/var/run/treemgr/treemgr.sock")
                    m_connectors.emplace_back(std::tuple(ACE_SOCK_Stream(), connector, ACE_SOCK_Connector(), serviceType));
                } else {

                    ACE_INET_Addr connector;
                
                    if(IP.length()) {
                        addr = IP;
                        addr += ":";
                        addr += std::to_string(PORT);
                        connector.set_address(addr.c_str(), addr.length());
                    } else {
                        addr = std::to_string(PORT);
                        connector.set_port_number(PORT);
                    }

                    m_connectors.emplace_back(std::tuple(ACE_SOCK_Stream(), connector, ACE_SOCK_Connector(), serviceType));
                }
            }
        }

        void createAcceptorServices(const std::vector<std::tuple<std::string, std::uint16_t, service>>& services) {

            for(const auto& [IP, PORT, serviceType]: services) {

                std::string addr;
                addr.clear();
                ACE_INET_Addr listen;
                if(IP.length()) {
                    addr = IP;
                    addr += ":";
                    addr += std::to_string(PORT);
                    listen.set_address(addr.c_str(), addr.length());
                } else {
                    addr = std::to_string(PORT);
                    listen.set_port_number(PORT);
                }

                m_acceptors.emplace_back(std::tuple(ACE_SOCK_Stream(), listen, ACE_SOCK_Acceptor(), serviceType));
            }
        }

        std::int32_t startAcceptorServices() {
            std::int32_t reuse_addr = 1;
            for(auto& [stream, listen, acceptor, serviceType] : m_acceptors) {

                if(acceptor.open(listen, reuse_addr) < 0 ) {
                    ACE_DEBUG((LM_DEBUG, ACE_TEXT("%D [Acceptor:%t] %M %N:%l failed: opening of port %d hostname %s\n"), 
                               listen.get_port_number(), listen.get_host_name()));
                } else {
                    //start listening for new connection.
                    ACE_Reactor::instance()->register_handler(acceptor.get_handle(), this, 
                                                    ACE_Event_Handler::ACCEPT_MASK | 
                                                    ACE_Event_Handler::TIMER_MASK |
                                                    ACE_Event_Handler::SIGNAL_MASK);
                }

            }
        }

        std::int32_t startConnectorServices() {
            std::int32_t reuse_addr = 1;
            ACE_Time_Value to = {0,0};
            for(auto& [stream, address, connector, serviceType] : m_connectors) {

                if(connector.connect(stream, address, &to) < 0) {
                    if(EWOULDBLOCK == errno) {
                        //For non-blocking socket
                    }
                    ACE_DEBUG((LM_DEBUG, ACE_TEXT("%D [Connector:%t] %M %N:%l failed: opening of port %d hostname %s\n"), 
                               listen.get_port_number(), listen.get_host_name()));
                } else {
                    ACE_Reactor::instance()->register_handler(stream.get_handle(), this, 
                                                    ACE_Event_Handler::CONNECT_MASK | 
                                                    ACE_Event_Handler::TIMER_MASK |
                                                    ACE_Event_Handler::SIGNAL_MASK);
                }

            }
        }

    private:
        std::vector<std::tuple<ACE_SOCK_Stream, ACE_Addr, ACE_SOCK_Acceptor, service>> m_acceptors;
        std::vector<std::tuple<ACE_SOCK_Stream, ACE_Addr, ACE_SOCK_Connector, service>> m_connectors;
        std::unordered_map<std::string, std::string> m_config;
        std::unordered_map<std::int32_t, ConnectedServices> m_connectedServices;

};


#endif /* __uniimage__hpp__ */
