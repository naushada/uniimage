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
#include <memory>
#include <thread>
#include <sstream>
#include <unordered_map>
#include <tuple>
#include <getopt.h>
#include <atomic>

#include "http.hpp"

namespace noor {
    class Uniimage;
    class NetInterface;
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

        enum socket_type: std::uint32_t {
            UNIX = 0,
            TCP = 1,
            TCP_ASYNC = 2,
            UDP = 3,
            UDP_ASYNC = 4
            
        };

        NetInterface(std::unique_ptr<NetInterface> hook);
        ~NetInterface();
        void close();
        std::int32_t tcp_client(const std::string& IP, std::uint16_t PORT, bool isAsync=true);
        std::int32_t tcp_client_async(const std::string& IP, std::uint16_t PORT);
        std::int32_t udp_client(const std::string& IP, std::uint16_t PORT);
        std::int32_t uds_client(const std::string& PATH="/var/run/treemgr/treemgr.sock");
        std::int32_t tcp_server(const std::string& IP, std::uint16_t PORT);
        std::int32_t udp_server(const std::string& IP, std::uint16_t PORT);
        std::int32_t web_server(const std::string& IP, std::uint16_t PORT);
        std::int32_t start_client(std::uint32_t timeout_in_ms, std::vector<std::tuple<std::unique_ptr<NetInterface>, socket_type>>);
        std::int32_t start_server(std::uint32_t timeout_in_ms, std::vector<std::tuple<std::unique_ptr<NetInterface>, socket_type>>);
        std::int32_t tcp_rx(std::string& data);
        emp uds_rx();
        std::int32_t web_rx(std::string& data);
        std::int32_t udp_rx(std::string& data);

        virtual std::int32_t onReceive(std::string in) = 0;
        virtual std::int32_t onClose(std::string in) = 0;


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
        void add_element_to_cache(auto elm) {
            m_response_cache.push_back(elm);
        }

        void update_response_to_cache(std::int32_t id, std::string rsp) {
            std::find_if(response_cache().begin(), response_cache().end(), [&](auto& inst) {
                if(std::get<cache_element::MESSAGE_ID>(inst) == id) {
                    std::get<cache_element::RESPONSE>(inst) = rsp;
                    return(true);
                }
                return(false);
            });
        }
        void connected_client(client_connection st) {
            m_connected_clients.insert(std::make_pair(handle(), st));
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

        auto& inet_server() {
            return(m_inet_server);
        }

        auto& inet_peer() {
            return(m_inet_peer);
        }

        auto& un_server() {
            return(m_un_server);
        }
        
    private:
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
        //key = fd, Value = <fd, IP, PORT, RxBytes, TxBytes, timestamp>
        std::unordered_map<std::int32_t, std::vector<std::tuple<std::int32_t, std::string, std::int32_t, std::int32_t, std::int32_t, std::int32_t>>> m_web_connections;
        std::unordered_map<std::int32_t, std::vector<std::tuple<std::int32_t, std::string, std::int32_t, std::int32_t, std::int32_t, std::int32_t>>> m_tcp_connections;
        std::unique_ptr<NetInterface> m_hook;

};

#endif /* __uniimage__hpp__ */
