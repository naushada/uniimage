#ifndef __uniimage__cc__
#define __uniimage__cc__

#include "ds_client.hpp"
#include "http.hpp"

std::int32_t noor::Uniimage::web_server(const std::string& IP, std::uint16_t PORT) {
    /* Set up the address we're going to bind to. */
    bzero(&m_web_server, sizeof(m_web_server));
    m_web_server.sin_family = AF_INET;
    m_web_server.sin_port = htons(PORT);
    m_web_server.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_web_server.sin_zero, 0, sizeof(m_web_server.sin_zero));
    auto len = sizeof(m_web_server);

    std::int32_t channel = ::socket(AF_INET, SOCK_STREAM, 0);
    if(channel < 0) {
        std::cout << "Creation of INET socket Failed" << std::endl;
        return(-1);
    }

    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "Error: Could not set reuse address option on INET socket!" << std::endl;
        return(-1);
    }
    auto ret = ::bind(channel, (struct sockaddr *)&m_web_server, sizeof(m_web_server));
    if(ret < 0) {
        std::cout << "bind to IP: " << IP << " PORT: " << PORT << " Failed" <<std::endl;
	return(-1);
    }

    if(listen(channel, 10) < 0) {
        std::cout << "listen to channel: " << channel << " Failed" <<std::endl;
	return(-1);
    }
    web_server_fd(channel);
    m_web_server_port = PORT;
    return(0);
}

std::int32_t noor::Uniimage::tcp_server(const std::string& IP, std::uint16_t PORT) {
    /* Set up the address we're going to bind to. */
    bzero(&m_server_addr, sizeof(m_server_addr));
    m_server_addr.sin_family = AF_INET;
    m_server_addr.sin_port = htons(PORT);
    m_server_addr.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_server_addr.sin_zero, 0, sizeof(m_server_addr.sin_zero));
    auto len = sizeof(m_server_addr);

    std::int32_t channel = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(channel < 0) {
        std::cout << "Creation of INET socket Failed" << std::endl;
        return(-1);
    }

    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "Error: Could not set reuse address option on INET socket!" << std::endl;
        return(-1);
    }
    auto ret = ::bind(channel, (struct sockaddr *)&m_server_addr, sizeof(m_server_addr));
    if(ret < 0) {
        std::cout << "bind to IP: " << IP << " PORT: " << PORT << " Failed" <<std::endl;
	return(-1);
    }

    if(listen(channel, 10) < 0) {
        std::cout << "listen to channel: " << channel << " Failed" <<std::endl;
	return(-1);
    }
    tcp_server_fd(channel);
    m_tcp_server_port = PORT;
    return(0);
}

std::string noor::Uniimage::serialise(noor::Uniimage::EMP_COMMAND_TYPE cmd_type, noor::Uniimage::EMP_COMMAND_ID cmd, const std::string& req) {
    cmd = (noor::Uniimage::EMP_COMMAND_ID)(((cmd_type & 0x3 ) << 12) | (cmd & 0xFFF));

    std::uint32_t payload_len = req.length();
    std::cout << "Payload length: " << payload_len << " REQUEST: " << req << std::endl;
    cmd = (noor::Uniimage::EMP_COMMAND_ID)htons(cmd);
    ++m_message_id;
    auto message_id = htons(m_message_id);
    payload_len = htonl(payload_len);
    std::stringstream data("");
    
    data.write (reinterpret_cast <char *>(&cmd), sizeof(cmd));
    data.write (reinterpret_cast <char *>(&message_id), sizeof(message_id));
    data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
    data << req;
    return(data.str());
}

std::string noor::Uniimage::packArguments(const std::string& prefix, std::vector<std::string> fields, std::vector<std::string> filter) {
    std::stringstream rsp("");
    std::string result("");

    if(prefix.empty()) {
        //This can't be empty
        return(std::string());
    } else {
	if(true == m_is_reg_ds) {
	    // First argument will be callback , hence blank
            rsp << "[\"\", \"" <<  prefix << "\"";
	} else {
            rsp << "[\"" <<  prefix << "\"";
	}
        result += rsp.str();
        rsp.str("");
    }
    if(!fields.empty()) {
        if(1 == fields.size()) {
            rsp << ",[\"" << fields.at(0) << "\"]";
            result += rsp.str();
	    rsp.str("");
        } else {
            rsp << ",[";
            for(const auto& elm: fields) {
                rsp << "\"" << elm << "\",";
            }
            result += rsp.str().substr(0, rsp.str().length() - 1);
            result += "]";
            rsp.str("");
        }
    }
    //filters ... field_name__eq
    if(!filter.empty()) {
        if(1 == filter.size()) {
            rsp << ",{\"" << filter.at(0) << "\"}";
            result += rsp.str();
            rsp.str("");
        } else {
            rsp << ",{";
            for(const auto& elm: filter) {
                rsp << "\"" << elm << "\",";
            }
            result += rsp.str().substr(0, rsp.str().length() - 1);
            result += "}";
            rsp.str("");
        }
    }
    result +="]";
    return(result);
}

std::int32_t noor::Uniimage::registerGetVariable(const std::string& prefix, std::vector<std::string> fields, std::vector<std::string> filter) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::RegisterGetVariable;
    m_is_reg_ds = true; 
    std::string rsp = packArguments(prefix, fields, filter);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = uds_tx(uds_client_fd(), data);
    add_element(cmd_type, cmd, m_message_id, prefix); 
    m_is_reg_ds = false; 
    return(ret);

}

std::int32_t noor::Uniimage::getSingleVariable(const std::string& prefix) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::SingleGetVariable;
    
    std::string rsp = packArguments(prefix);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = uds_tx(uds_client_fd(), data); 
    add_element(cmd_type, cmd, m_message_id, prefix); 
    
    return(ret);
}

std::int32_t noor::Uniimage::getVariable(const std::string& prefix, std::vector<std::string> fields, std::vector<std::string> filter) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::GetVariable;

    std::string rsp = packArguments(prefix, fields, filter);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = uds_tx(uds_client_fd(), data);
     
    add_element(cmd_type, cmd, m_message_id, prefix);
    return(ret);
}

std::int32_t noor::Uniimage::tcp_tx(std::int32_t channel, const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;
    auto payload_len = htonl(req_len);
    std::stringstream data("");
    data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
    data << req;
    req_len = data.str().length();
    do {
        len = send(channel, data.str().data() + offset, req_len - offset, 0);
        if(len < 0) {
            offset = len;
            break;
        }
        offset += len;
    } while(offset != req_len);

    if(offset == req_len) {
        std::cout << "Request sent to TCP Server successfully" << std::endl;
    }
    return(offset);
}

std::int32_t noor::Uniimage::uds_tx(std::int32_t channel, const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;

    do {
        len = send(channel, req.data() + offset, req_len - offset, 0);
        if(len < 0) {
            offset = len;
            break;
        } 
        offset += len;
    } while(offset != req_len);

    if(offset == req_len) {
        for(std::int32_t idx = 0; idx < 8; ++idx) {
            printf("%X ", req.c_str()[idx]);
        }
        std::string ss(reinterpret_cast<const char *>(&req.c_str()[8]));
        std::cout << "Query pushed to DS ==> " << ss << std::endl;
    }
    return(offset);
}

std::int32_t noor::Uniimage::web_tx(std::int32_t channel, const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;

    do {
        len = send(channel, req.data() + offset, req_len - offset, 0);
        if(len < 0) {
            offset = len;
            break;
        } 
        offset += len;
    } while(offset != req_len);

    return(offset);
}

std::string noor::Uniimage::tcp_rx(std::int32_t handle) {
    std::array<char, 8> arr;
    arr.fill(0);
    std::int32_t len = -1;
    //read 4 bytes - the payload length
    len = recv(handle, arr.data(), sizeof(std::int32_t), 0);
    if(!len) {
        std::cout << "line: " << __LINE__ << " closed" << std::endl;
        return(std::string());
    } else if(len > 0) {
        std::uint32_t payload_len; 
        std::istringstream istrstr;
        istrstr.rdbuf()->pubsetbuf(arr.data(), len);
        istrstr.read(reinterpret_cast<char *>(&payload_len), sizeof(payload_len));
        std::uint32_t offset = 0;
        payload_len = ntohl(payload_len);
        std::cout << "line: " << __LINE__ << "tcp payload length: " << payload_len << std::endl;

        std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
        do {
            len = recv(handle, (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
            if(len < 0) {
                break;
            }
            offset += len;
        } while(offset != payload_len);
                
        if(offset == payload_len) {
            std::string ss((char *)payload.get(), payload_len);
            std::cout << "From TCP Client Received: " << ss << std::endl;
            return(ss);
        }
    }
    return(std::string());
}

noor::Uniimage::emp_t noor::Uniimage::uds_rx(std::int32_t handle) {
    std::uint16_t command;
    std::uint16_t message_id;
    std::uint32_t payload_size;
    std::uint16_t type;
    std::string response;
    std::array<char, 16> arr; 
    std::uint8_t EMP_HDR_SIZE = 8;
    arr.fill(0);

    auto len = recv(handle, arr.data(), EMP_HDR_SIZE, 0);
    if(len == EMP_HDR_SIZE) {
        //parse emp header
        std::istringstream istrstr;
        istrstr.rdbuf()->pubsetbuf(arr.data(), len);
        istrstr.read(reinterpret_cast<char *>(&command), sizeof(command));
        command = ntohs(command);
        type = (command >> 14) & 0x3;
        command &= 0xFFF;
        istrstr.read(reinterpret_cast<char *>(&message_id), sizeof(message_id));
        istrstr.read(reinterpret_cast<char *>(&payload_size), sizeof(payload_size));
        message_id = ntohs(message_id);
        payload_size = ntohl(payload_size);

        std::cout <<std::endl << "type: " << type << " command: " << command << " message_id: " << message_id << " payload_size: " << payload_size << std::endl;
        std::uint32_t offset = 0;
        std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_size);

        do {
            len = recv(handle, (void *)(payload.get() + offset), (size_t)(payload_size - offset), 0);
            if(len < 0) {
                break;
            }
            offset += len;
        } while(offset != payload_size);

        if(offset == payload_size) {
            std::string ss((char *)payload.get(), payload_size);
            std::cout << "Payload: " << ss << std::endl;
            emp_t res;
            res.m_type = type;
            res.m_command = command;
            res.m_message_id = message_id;
            res.m_response = ss;
            return(res);
        }
    }
    return(emp_t {});
}

std::string noor::Uniimage::web_rx(std::int32_t handle) {
    std::array<char, 1024> arr;
    arr.fill(0);
    std::int32_t len = -1;
    len = recv(handle, arr.data(), 1024, 0);
    if(!len) {
        std::cout << "function: "<<__FUNCTION__ << " line: " << __LINE__ << " closed" << std::endl;
    } else if(len > 0) {
        std::string ss(arr.data(), len);
        Http http(ss);
        std::cout << "line: " << __LINE__ << " URI: "   << http.uri()    << std::endl;
        std::cout << "line: " << __LINE__ << " Header " << http.header() << std::endl;
        std::cout << "line: " << __LINE__ << " Body "   << http.body()   << std::endl;
        std::uint32_t offset = 0;
        auto cl = http.value("Content-Length");
        size_t payload_len = 0;

        if(!cl.length()) {
            std::cout << "line: " << __LINE__ << " Content-Length is not present" << std::endl;
            auto response = build_web_response(http);
            if(!response.length()) {
                web_tx(handle, response);
                return(std::string("success"));
            }
        } else {
            std::cout << "function: "<< __FUNCTION__ << " line: " << __LINE__ <<" value of Content-Length " << cl << std::endl;
            payload_len = std::stoi(cl);
            if(len == (payload_len + http.header().length())) {
                //We have received the full HTTP packet
                auto response = build_web_response(http);
                if(response.length()) {
                    web_tx(handle, response);
                    return(std::string("success"));
                }
            } else {
                //compute the effective length
                payload_len = (std::stoi(cl) + http.header().length() - len);
                std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
                std::int32_t tmp_len = 0;
                do {
                    tmp_len = recv(handle, (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
                    if(tmp_len < 0) {
                        break;
                    }
                    offset += tmp_len;
                    
                } while(offset != payload_len);
                if(offset == payload_len) {
                    std::string header(arr.data(), len);
                    std::string ss((char *)payload.get(), payload_len);
                    std::string request = header + ss;
                    std::cout << "function: "<<__FUNCTION__ <<" line: " <<__LINE__ << " From Web Client Received: " << request << std::endl;
                    Http http(request);
                    auto response = build_web_response(http);
                    auto res = web_tx(handle, response);
                    return("success");
                }
            }
        }
    }
    return(std::string());
}

std::string noor::Uniimage::build_web_response(Http& http) {
    //Build HTTP Response
    std::cout << "URI: " << http.uri() << " method: " << http.method() << std::endl;
    std::stringstream ss("");
    std::string payload("<html><title></title><head></head><body><h2>Redirecting to http://10.20.129.11</h2></body></html>");
    ss << "HTTP/1.1 301 Moved Permanently\r\n"
       << "Location: https://10.20.129.111:443\r\n"
       << "Content-length: " << payload.length() << "\r\n"
       << "Connection: close\r\n"
       << "Cookie: unity_token=IC3wWl66tT3XrqO88iLBSxCYbuxhPvGz; unity_login=admin; last_connection={\"success_last\":\"Sat Apr  8 03:47:22 2023\",\"success_from\":\"192.168.1.100\",\"failures\":0}" 
       << "\r\n\r\n"
       << payload;

    std::cout << "The Web Response is " << ss.str() << std::endl;
    return(ss.str());
}

void noor::Uniimage::add_element(std::uint16_t type, std::uint16_t cmd, std::uint16_t message_id, std::string prefix, std::string response) {
    m_ds_request_list.push_back(std::make_tuple(type, cmd, message_id, prefix, response));
}

std::int32_t noor::Uniimage::create_and_connect_tcp_socket(const std::string& IP, std::uint16_t port) {
    //TCP Client .... 
    /* Set up the address we're going to bind to. */
    bzero(&m_server_addr, sizeof(m_server_addr));
    m_server_addr.sin_family = AF_INET;
    m_server_addr.sin_port = htons(port);
    m_server_addr.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_server_addr.sin_zero, 0, sizeof(m_server_addr.sin_zero));
    auto len = sizeof(m_server_addr);

    std::int32_t channel = ::socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
    if(channel < 0) {
        std::cout << "line: " << __LINE__ <<" Creation of INET socket Failed" << std::endl;
        return(-1);
    }
    tcp_client_fd(channel);
    tcp_client(client_connection::Disconnected);

    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << " Error: Could not set reuse address option on INET socket!" << std::endl;
        close(tcp_client_fd());
        tcp_client_fd(-1);
        return(-1);
    }
    
    auto rc = ::connect(channel, (struct sockaddr *)&m_server_addr, len);
    if(rc == -1) {
        if(errno == EINPROGRESS) {    
            std::cout << "line: " << __LINE__ << " Connection is in-progress: "<< std::endl;
            tcp_client(client_connection::Inprogress);
            return(0);

        } else if(errno == ECONNREFUSED) {
            //Server is not strated yet
            std::cout << "line: " << __LINE__ << " Connect is refused errno: "<< std::strerror(errno) << std::endl;
            close(tcp_client_fd());
            tcp_client_fd(-1);
            return(-1);

        } else {
            std::cout << "line: " << __LINE__ << " Connect is failed errno: "<< std::strerror(errno) << std::endl;
            close(tcp_client_fd());
            tcp_client_fd(-1);
            return(-1);
        }
    } else {
        tcp_client(client_connection::Connected);
        return(0);
    }
}

std::int32_t noor::Uniimage::start_client() {
    int conn_id   = -1;
    fd_set fdList;
    fd_set fdWrite;
    fd_set fdExcep;

    while (1) {
        /* A timeout for 100ms*/ 
        struct timeval to;
        to.tv_sec = 0;
        to.tv_usec = 100;
        FD_ZERO(&fdList);
        FD_ZERO(&fdWrite);

        std::int32_t max_fd = uds_client_fd();
        FD_SET(uds_client_fd(), &fdList);

        if(udp_client_fd() > 0) {
            FD_SET(udp_client_fd(), &fdList);
            max_fd = (max_fd > udp_client_fd()) ? max_fd : udp_client_fd();
        }
        if(tcp_client_fd() > 0 && tcp_client() == client_connection::Connected) {
            FD_SET(tcp_client_fd(), &fdList);
            max_fd = (max_fd > tcp_client_fd()) ? max_fd : tcp_client_fd();
        } else if(tcp_client_fd() > 0 && tcp_client() == client_connection::Inprogress) {
            FD_SET(tcp_client_fd(), &fdWrite);
            max_fd = (max_fd > tcp_client_fd()) ? max_fd : tcp_client_fd();
        }

        conn_id = ::select((max_fd + 1), (fd_set *)&fdList, (fd_set *)&fdWrite, (fd_set *)&fdExcep, (struct timeval *)&to);
        if(conn_id > 0) {
            // Received on Unix Socket
            if(uds_client_fd() > 0 && FD_ISSET(uds_client_fd(), &fdList)) {
                //Received response from Data store
                std::string request("");
                std::cout << "From DS line: " << __LINE__<<" Response received " << std::endl;
                auto req = uds_rx(uds_client_fd());
                if(!req.m_response.length()) {
                    close(uds_client_fd());
                    uds_client(client_connection::Disconnected);
                    std::cout << "Data store is down" << std::endl;
                    exit(0);
                } else {
                    std::cout << "line: " << __LINE__ << " Caching the response" << std::endl;
                    //Cache the response and will be sent later when TCP connection is established or upon timed out
                    auto it = std::find_if(m_ds_request_list.begin(), m_ds_request_list.end(), [&](auto &inst) {
                        if(req.m_message_id == std::get<2>(inst)) {
                            //Update the recieved response
                            std::get<4>(inst) = req.m_response;
                            return(true);
                        }
                            return(false);
                    });
                }
            }
            //Received on UDP Socket
            if(udp_client_fd() > 0 && FD_ISSET(udp_client_fd(), &fdList)) {
                //From UDP Server
                std::string ret("");
                //auto ret = udp_rx(udp_client_fd());
                std::cout << "line: " << __LINE__ << "Xreating issue " << std::endl;
                if(ret.length()) {
                    //Got Response from UDP client
                }
            }
            //The TCP client might be connected
            if(tcp_client_fd() > 0 && FD_ISSET(tcp_client_fd(), &fdWrite)) {
                //TCP connection established successfully.
                //Push changes if any now
                //When the connection establishment (for non-blocking socket) encounters an error, the descriptor becomes both readable and writable (p. 530 of TCPv2).
                socklen_t optlen;
                std::int32_t optval = -1;
                optlen = sizeof (optval);
                if(!getsockopt(tcp_client_fd(), SOL_SOCKET, SO_ERROR, &optval, &optlen)) {
                    struct sockaddr_in peer;
                    socklen_t sock_len = sizeof(peer);
                    memset(&peer, 0, sizeof(peer));
                    auto ret = getpeername(tcp_client_fd(), (struct sockaddr *)&peer, &sock_len);
                    if(ret < 0 && errno == ENOTCONN) {
                        std::cout << "line: " << __LINE__ << "Async connect failed " << std::endl;
                        close(tcp_client_fd());
                        tcp_client(client_connection::Disconnected);
                        tcp_client_fd(-1);
                    } else {
                        //TCP Client is connected 
                        tcp_client(client_connection::Connected);
                        std::cout << "line: " << __LINE__ << " function: " << __FUNCTION__ << " Connected successfully" << std::endl;
                        FD_CLR(tcp_client_fd(), &fdWrite);
                        FD_ZERO(&fdWrite);

                        if(!m_ds_request_list.empty()) {
                            for(const auto& ent: m_ds_request_list) {
                                std::string payload = std::get<4>(ent);
                                //don't push to TCP server If response is awaited.
                                if(payload.compare("default")) {
                                    std::uint32_t payload_len = payload.length();
                                    payload_len = htonl(payload_len);
                                    std::stringstream data("");
                                    data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
                                    data << payload;
                                    tcp_tx(tcp_client_fd(), data.str());
                                }
                            }
                        }
                    }
                }
            }

            if(tcp_client_fd() > 0 && FD_ISSET(tcp_client_fd(), &fdList)) {
                //From TCP Server
                std::string request("");
                auto req = tcp_rx(tcp_client_fd());
                std::cout << "line: "<< __LINE__ << " Response received from TCP Server length:" << req.length() << std::endl;
                if(!req.length() && tcp_client() == client_connection::Connected) {
                    close(tcp_client_fd());
                    tcp_client(client_connection::Disconnected);
                    tcp_client_fd(-1);
                } else {
                    //Got from TCP server 
                    std::cout <<"line: " << __LINE__ << "Received from TCP server length: " << req.length() << std::endl;
                }
            }
        } 
        else if(!conn_id) {
            //time out happens
            if(tcp_client_fd() < 0 && tcp_client() == client_connection::Disconnected && !m_config["protocol"].compare("tcp)")) {
                create_and_connect_tcp_socket(m_config["server-ip"], std::stoi(m_config["server-port"]));
            }

            if(udp_client_fd() > 0  && !m_config["protocol"].compare("udp)")) {
                for(auto it = m_ds_request_list.begin(); it != m_ds_request_list.end(); ++it) {
                    std::string payload = std::get<4>(*it);
                    //don't push to TCP server If response is awaited.
                    if(payload.compare("default")) {
                        if(udp_tx(udp_client_fd(), payload) > 0) {
                            //Sent successfully
                            it = m_ds_request_list.erase(it);
                        }
                    }
                }
            }
        }
    } /* End of while loop */
}

std::int32_t noor::Uniimage::start_server() {
    //Read required Key's value from Data Store.
    int conn_id   = -1;
    fd_set fdList;
    //newFd, IP, PORT,
    std::unordered_map<std::int32_t, std::tuple<std::int32_t, std::string, std::uint16_t>> tcp_conn;
    std::unordered_map<std::int32_t, std::tuple<std::int32_t, std::string, std::uint16_t>> web_conn;
    while (1) {
        /* A timeout for 100ms*/ 
        struct timeval to;
        to.tv_sec = 0;
        to.tv_usec = 100;
        FD_ZERO(&fdList);
        std::int32_t max_fd = web_server_fd();
        FD_SET(web_server_fd(), &fdList);

        if(tcp_server_fd() > 0) {
            max_fd = max_fd > tcp_server_fd() ? max_fd : tcp_server_fd();
            FD_SET(tcp_server_fd(), &fdList);
        }

        if(udp_server_fd() > 0) {
            max_fd = max_fd > udp_server_fd() ? max_fd : udp_server_fd();
            FD_SET(udp_server_fd(), &fdList);
        }

        if(!tcp_conn.empty()){
            for(const auto& elm: tcp_conn) {
                max_fd = max_fd > std::get<0>(elm) ? max_fd : std::get<0>(elm);
                FD_SET(std::get<0>(elm), &fdList);
            }
        }

        if(!web_conn.empty()) {
            for(const auto& elm: web_conn) {
                max_fd = max_fd > elm.first ? max_fd : elm.first;
                FD_SET(elm.first, &fdList);
            }
        }

        conn_id = ::select((max_fd + 1), (fd_set *)&fdList, (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)&to);

        if(conn_id > 0) {
            if(tcp_server_fd() > 0 && FD_ISSET(tcp_server_fd(), &fdList)) {
                // accept a new connection 
                struct sockaddr_in peer;
                socklen_t peer_len = sizeof(peer);
                auto newFd = ::accept(tcp_server_fd(), (struct sockaddr *)&peer, &peer_len);
                if(newFd > 0) {
                    std::string IP(inet_ntoa(peer.sin_addr));
                    tcp_conn.insert(std::make_pair(newFd, std::make_tuple(newFd, IP, ntohs(peer.sin_port))));
                    std::cout << "line: " << __LINE__ << " chnnel: " << newFd << " IP: " << IP <<" port:" << ntohs(peer.sin_port) << std::endl;
                }
            } 
            if(FD_ISSET(web_server_fd(), &fdList)) {
                // accept a new connection 
                struct sockaddr_in peer;
                socklen_t peer_len = sizeof(peer);
                auto newFd = ::accept(web_server_fd(), (struct sockaddr *)&peer, &peer_len);
                if(newFd > 0) {
                    std::string IP(inet_ntoa(peer.sin_addr));
                    web_conn.insert(std::make_pair(newFd, std::make_tuple(newFd, IP, ntohs(peer.sin_port))));
                    auto ent = web_conn[newFd];
                    std::cout << "line: "<< __LINE__ <<" new web connId: " << std::get<0>(ent) << " IP: " << std::get<1>(ent) << " PORT: " << std::get<2>(ent) << std::endl;
                    FD_SET(newFd, &fdList);
                }
            }
            if(udp_server_fd() > 0 && FD_ISSET(udp_server_fd(), &fdList)) {
                auto res = udp_rx(udp_server_fd());
                if(res.length()) {
                    std::cout << "line: " << __LINE__ << " Received from UDP Client " << std::endl;
                    std::cout << "line: " << __LINE__ << " Response: " << res;
                }
            }
            if(!tcp_conn.empty()) {
                for(const auto &elm: tcp_conn) {
                    auto channel = std::get<0>(elm);
                    if(FD_ISSET(channel, &fdList)) {
                        //From TCP Client
                        std::string request("");
                        std::cout << "line: "<< __LINE__ << " Response received from TCP client: " << std::endl;
                        auto req = tcp_rx(channel);
                        if(!req.length()) {
                            //client is closed now
                            std::cout << "line: " << __LINE__ << " req.length: " << req.length() <<std::endl; 
                            close(channel);
                            auto it = tcp_conn.erase(channel);
                        } else {
                            std::cout << "line: " << __LINE__ << " Data TCP Server Received: " << req << std::endl;
                        }
                    }
                }
            }
            if(!web_conn.empty()) {
                for(const auto &elm: web_conn) {
                auto channel = std::get<0>(elm);
                    if(FD_ISSET(channel, &fdList)) {
                        //From Web Client 
                        std::string request("");
                        std::cout <<"line: " << __LINE__ << " Request from Web client received on channel "<< channel << std::endl;
                        auto req = web_rx(channel);
                        if(!req.length()) {
                            //client is closed now 
                            close(channel);
                            auto it = web_conn.erase(channel);
                        }
                    }
                }
            }
        } /*conn_id > 0*/
    } /* End of while loop */
}

//***************** UDP *******************
std::int32_t noor::Uniimage::udp_client(const std::string& IP, std::uint16_t port) {
    //UDP Client .... 
    /* Set up the address we're going to bind to. */
    bzero(&m_server_addr, sizeof(m_server_addr));
    m_server_addr.sin_family = AF_INET;
    m_server_addr.sin_port = htons(port);
    m_server_addr.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_server_addr.sin_zero, 0, sizeof(m_server_addr.sin_zero));

    std::int32_t channel = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(channel < 0) {
        std::cout << "line: " << __LINE__ <<" Creation of INET socket Failed" << std::endl;
        return(-1);
    }
    udp_client_fd(channel);
    
    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << " Error: Could not set reuse address option on INET socket!" << std::endl;
        close(udp_client_fd());
        udp_client_fd(-1);
        return(-1);
    }
    return(0);
}

std::int32_t noor::Uniimage::udp_server(const std::string& IP, std::uint16_t port) {
    //UDP Server .... 
    /* Set up the address we're going to bind to. */
    bzero(&m_server_addr, sizeof(m_server_addr));
    m_server_addr.sin_family = AF_INET;
    m_server_addr.sin_port = htons(port);
    m_server_addr.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_server_addr.sin_zero, 0, sizeof(m_server_addr.sin_zero));
    auto len = sizeof(m_server_addr);

    std::int32_t channel = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(channel < 0) {
        std::cout << "line: " << __LINE__ <<" Creation of INET socket Failed" << std::endl;
        return(-1);
    }
    udp_server_fd(channel);
    
    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << " Error: Could not set reuse address option on INET socket!" << std::endl;
        close(udp_server_fd());
        udp_server_fd(-1);
        return(-1);
    }

    auto ret = ::bind(channel, (struct sockaddr *)&m_server_addr, len);
    if(ret < 0) {
        std::cout << "line: "<< __LINE__ << " bind to UDP protocol failed" << std::endl;
        close(udp_server_fd());
        udp_server_fd(-1);
        return(-1);
    }
    return(0);
}

std::int32_t noor::Uniimage::udp_tx(std::int32_t channel, const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t payload_len = req.length();
    std::int32_t len = -1;
    auto total_len = htonl(payload_len);
    std::stringstream data("");
    data.write(reinterpret_cast <char *>(&total_len), sizeof(std::int32_t));
    data << req;
    payload_len = data.str().length();

    do {
        len = sendto(channel, data.str().data() + offset, payload_len - offset, 0, (struct sockaddr *)&m_server_addr, sizeof(m_server_addr));
        if(len < 0) {
            offset = len;
            break;
        }
        offset += len;
    } while(offset != payload_len);

    if(offset > 0 && offset == payload_len) {
        std::cout <<"line: " << __LINE__ << " Request sent to UDP Server successfully length: "<< offset << std::endl;
    }
    return(offset);
}

std::string noor::Uniimage::udp_rx(std::int32_t channel) {
    std::array<char, 8> arr;
    arr.fill(0);
    std::int32_t len = -1;
    struct sockaddr_in peer;
    socklen_t peer_addr_len = sizeof(peer);

    len = recvfrom(channel, arr.data(), sizeof(std::int32_t), MSG_PEEK, (struct sockaddr *)&peer, &peer_addr_len);
    if(!len) {
        std::cout << "line: " << __LINE__ << " closed" << std::endl;
        return(std::string());
    } else if(len > 0) {
        std::int32_t payload_len = 0; 
        std::istringstream istrstr;
        istrstr.rdbuf()->pubsetbuf(arr.data(), len);
        std::cout << "\nline: " << __LINE__ << " to be received bytes: " << len <<std::endl;
        istrstr.read(reinterpret_cast<char *>(&payload_len), sizeof(payload_len));
        std::uint32_t offset = 0;
        payload_len = ntohl(payload_len) + 4; //+4 for 4bytes of length prepended to payload
        std::cout << "line: " << __LINE__ << " udp payload length: " << payload_len << std::endl;

        std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);

        do {
            len = recvfrom(channel, (void *)(payload.get() + offset), (size_t)(payload_len - offset), MSG_WAITALL, (struct sockaddr *)&peer, &peer_addr_len);
            if(len < 0) {
                offset = len;
                break;
            }
            offset += len;
        } while(offset != payload_len);
                
        if(offset> 0 && offset == payload_len) {
            std::string ss((char *)payload.get() + 4, payload_len-4);
            //std::cout << "line: "<< __LINE__ << " From UDP Client Received: " << ss << std::endl;
            return(ss);
        }
    }
    return(std::string());
}

std::vector<struct option> options = {
    {"role",                      required_argument, 0, 'r'},
    {"server-ip",                 required_argument, 0, 'i'},
    {"server-port",               required_argument, 0, 'p'},
    {"web-port",                  required_argument, 0, 'w'},
    {"wan-interface-instance",    required_argument, 0, 'a'},
    {"protocol",                  required_argument, 0, 't'},
    {"self-ip",                   required_argument, 0, 's'},
    {"self-port",                 required_argument, 0, 'e'}
};

int main(std::int32_t argc, char *argv[]) {
    std::int32_t c;
    std::int32_t option_index;
    std::string role("");
    std::unordered_map<std::string, std::string> config;
    
    while ((c = getopt_long(argc, argv, "r:i:p:w:t:a:s:e:", options.data(), &option_index)) != -1) {
        switch(c) {
            case 'r':
            {
                role = optarg;
                if(role.compare("client") && (role.compare("server"))) {
                    std::cout << "Invalid value for --role, possible value is client or server "<< std::endl;
                    return(-1);
                }
                config.insert(std::make_pair("role", optarg));
            }
            break;
            case 'i':
            {
                config.insert(std::make_pair("server-ip", optarg));
            }
            break;
            case 'p':
            {
                config.insert(std::make_pair("server-port", optarg));
            }
            break;
            case 'w':
            {
                config.insert(std::make_pair("web-port", optarg));
            }
            break;
            case 'a':
            {
                config.insert(std::make_pair("wan-interface-instance", optarg));
            }
            break;
            case 't':
            {
                config.insert(std::make_pair("protocol", optarg));
            }
            break;
            case 's':
            {
                config.insert(std::make_pair("self-ip", optarg));
            }
            break;
            case 'e':
            {
                config.insert(std::make_pair("self-port", optarg));
            }
            break;

            default:
            {
                std::cout << "--role <client|server> " << std::endl
                          << "--server-ip <ip address of server> " << std::endl
                          << "--server-port <server port number> " << std::endl
                          << "--web-port  <server-web-port for http request> " << std::endl
                          << "--self-ip   <self ip for bind receive request> " << std::endl
                          << "--self-port <self port for bind to receive request> " << std::endl
                          << "--protocol  <tcp|udp|unix> " << std::endl
                          << "--wan-interface-instance <c1|c3|c4|c5|w1|w2|e1|e2|e3> " << std::endl;
                          return(-1);
            }
        }
    }
    
    noor::Uniimage unimanage(config);
    if(!config["role"].compare("client")) {
        unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}}, {{"radio.mode__eq\": \"sta"}});
        //unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}});
        //unimanage.getVariable("net.interface.wifi[]");
        //unimanage.getVariable("services.sms.provision.enable");
        //unimanage.registerGetVariable("services.sms.provision.enable");
        unimanage.getVariable("device", {{"machine"}, {"product"}, {"provisioning.serial"}});
        unimanage.getVariable("net.interface.common[]", {{"ipv4.address"}, {"ipv4.connectivity"}, {"ipv4.prefixlength"}});
        unimanage.start_client();
    } else if(!config["role"].compare("server")) {
        ///server 
        unimanage.start_server();
    }

    //noor::Dsclient inst;
    //std::atomic<std::uint16_t> message_id;
    //++message_id;
    //inst.tx(Dsclient::EMP_COMMAND_TYPE::Request, Dsclient::EMP_COMMAND_ID::SingleGetVariable, message_id, "[\"services.sms.provision.enable\"]");
    //inst.tx(Dsclient::EMP_COMMAND_TYPE::Request, Dsclient::EMP_COMMAND_ID::GetVariable, message_id, "[\"net.interface.cellular[]\"]");
    //inst.tx(Dsclient::EMP_COMMAND_TYPE::Request, Dsclient::EMP_COMMAND_ID::GetVariable, message_id, "[\"net.interface.common[]\"]");
    //inst.tx(Dsclient::EMP_COMMAND_TYPE::Request, Dsclient::EMP_COMMAND_ID::RegisterVariable, message_id, "[\"\", \"services.sms.provision.enable\"]");
    //++message_id;
    //inst.tx(Dsclient::EMP_COMMAND_TYPE::Request, Dsclient::EMP_COMMAND_ID::SetVariable, message_id, "[\"services.sms.provision.enable\", false]");
    //inst.start();
}


#endif /* __uniimage__cc__ */
