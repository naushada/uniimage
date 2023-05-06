#ifndef __uniimage__cc__
#define __uniimage__cc__

#include "uniimage.hpp"
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
            if(response.length()) {
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

        conn_id = ::select((max_fd + 1), (fd_set *)&fdList, (fd_set *)&fdWrite, (fd_set *)NULL, (struct timeval *)&to);
        if(conn_id > 0) {
            // Received on Unix Socket
            if(uds_client_fd() > 0 && FD_ISSET(uds_client_fd(), &fdList)) {
                //Received response from Data store
                std::string request("");
                std::cout << "From DS line: " << __LINE__<<" Response received " << std::endl;
                auto req = uds_rx(uds_client_fd());
                if(!req.m_response.length()) {
                    close(uds_client_fd());
                    m_client_list.erase(uds_client_fd());
                    uds_client_fd(-1);
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
                std::cout << "line: " << __LINE__ << " Xreating issue " << std::endl;
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
                        close(tcp_client_fd());
                        m_client_list.erase(tcp_client_fd());
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
                    m_client_list.erase(tcp_client_fd());
                    tcp_client_fd(-1);
                } else {
                    //Got from TCP server 
                    std::cout <<"line: " << __LINE__ << "Received from TCP server length: " << req.length() << std::endl;
                }
            }
        } 
        else if(!conn_id) {
            //time out happens
            if(tcp_client_fd() < 0 && !m_config["protocol"].compare("tcp")) {
                create_and_connect_tcp_socket(m_config["server-ip"], std::stoi(m_config["server-port"]));
            }

            if(udp_client_fd() > 0  && !m_config["protocol"].compare("udp")) {
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

/**
 * @brief 
 * 
 * @return std::int32_t 
 */
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
/**
 * @brief 
 * 
 * @param IP 
 * @param port 
 * @return std::int32_t 
 */
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
        m_client_list.erase(udp_client_fd());
        udp_client_fd(-1);
        return(-1);
    }
    return(0);
}

/**
 * @brief 
 * 
 * @param IP 
 * @param port 
 * @return std::int32_t 
 */
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
        m_client_list.erase(udp_client_fd());
        udp_server_fd(-1);
        return(-1);
    }
    return(0);
}

/**
 * @brief 
 * 
 * @param channel 
 * @param req 
 * @return std::int32_t 
 */
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

/**
 * @brief 
 * 
 * @param channel 
 * @return std::string 
 */
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

/**
 * @brief 
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(std::int32_t argc, char *argv[]) {
    std::int32_t c;
    std::int32_t option_index = 0;
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
                config.emplace(std::make_pair("role", optarg));
            }
            break;
            case 'i':
            {
                config.emplace(std::make_pair("server-ip", optarg));
            }
            break;
            case 'p':
            {
                config.emplace(std::make_pair("server-port", optarg));
            }
            break;
            case 'w':
            {
                config.emplace(std::make_pair("web-port", optarg));
            }
            break;
            case 'a':
            {
                config.emplace(std::make_pair("wan-interface-instance", optarg));
            }
            break;
            case 't':
            {
                config.emplace(std::make_pair("protocol", optarg));
            }
            break;
            case 's':
            {
                config.emplace(std::make_pair("self-ip", optarg));
            }
            break;
            case 'e':
            {
                config.emplace(std::make_pair("self-port", optarg));
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
 #if 0   
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
#endif

    //std::unique_ptr<noor::NetInterface> unimanage = std::make_unique<noor::NetInterface>();
    noor::NetInterface unimanage;
    std::vector<std::tuple<std::unique_ptr<noor::NetInterface>, noor::NetInterface::socket_type>> ent;
    ent.clear();
    //unimanage.set_config(config);

    if(!config["role"].compare("client")) {

        if(!config["protocol"].compare("tcp")) {
            ent.push_back({std::make_unique<TcpClient>(config), noor::NetInterface::socket_type::TCP_ASYNC});
        } else {
            ent.push_back({std::make_unique<UdpClient>(config), noor::NetInterface::socket_type::UDP});
        }
        ent.push_back({std::make_unique<UnixClient>(), noor::NetInterface::socket_type::UNIX});

        std::get<0>(ent.at(1))->getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}}, {{"radio.mode__eq\": \"sta"}});
        std::get<0>(ent.at(1))->getVariable("device", {{"machine"}, {"product"}, {"provisioning.serial"}});
        std::get<0>(ent.at(1))->getVariable("net.interface.common[]", {{"ipv4.address"}, {"ipv4.connectivity"}, {"ipv4.prefixlength"}});
        std::cout << "line: " << __LINE__ << " TCP_ASYNC: " << std::get<0>(ent.at(0))->handle() << " : " <<std::get<0>(ent.at(0))->connected_client(std::get<0>(ent.at(0))->handle())<< std::endl;
        unimanage.start_client(100, std::move(ent));

        #if 0
        unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}}, {{"radio.mode__eq\": \"sta"}});
        //unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}});
        //unimanage.getVariable("net.interface.wifi[]");
        //unimanage.getVariable("services.sms.provision.enable");
        //unimanage.registerGetVariable("services.sms.provision.enable");
        unimanage.getVariable("device", {{"machine"}, {"product"}, {"provisioning.serial"}});
        unimanage.getVariable("net.interface.common[]", {{"ipv4.address"}, {"ipv4.connectivity"}, {"ipv4.prefixlength"}});
        unimanage.start_client();
        #endif
    } else if(!config["role"].compare("server")) {
        ///server 
        if(!config["protocol"].compare("tcp")) {
            ent.push_back({std::make_unique<TcpServer>(config), noor::NetInterface::socket_type::TCP});
        } else if(!config["protocol"].compare("udp")) {
            ent.push_back({std::make_unique<UdpServer>(config), noor::NetInterface::socket_type::UDP});
        } else {
            //Don't know 
        }
        
        ent.push_back({std::make_unique<WebServer>(config), noor::NetInterface::socket_type::WEB});

        //std::unordered_map<std::string, std::string> out;
        //auto jArray = "{\"element\": [{\"key\":\"123456\", \"key1\":\"abcdefg\"}]}";
        //from_json_array_to_map(jArray, out);

        //ent.push_back({std::make_unique<UnixServer>(), noor::NetInterface::socket_type::UNIX});
        unimanage.start_server(100, std::move(ent));
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

std::int32_t noor::NetInterface::tcp_client_async(const std::string& IP, std::uint16_t PORT) {
    return(tcp_client(IP, PORT, true));
}

/**
 * @brief 
 * 
 * @param IP 
 * @param PORT 
 * @param isAsync 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::tcp_client(const std::string& IP, std::uint16_t PORT, bool isAsync) {
    /* Set up the address we're going to bind to. */
    bzero(&m_inet_server, sizeof(m_inet_server));
    m_inet_server.sin_family = AF_INET;
    m_inet_server.sin_port = htons(PORT);
    m_inet_server.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_inet_server.sin_zero, 0, sizeof(m_inet_server.sin_zero));
    auto len = sizeof(m_inet_server);
    std::int32_t channel = -1;

    if(isAsync) {
        channel = ::socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
        if(channel < 0) {
            std::cout << "line: " << __LINE__ <<" Creation of INET socket Failed" << std::endl;
            return(-1);
        }
    } else {
        channel = ::socket(AF_INET, SOCK_STREAM, 0);
        if(channel < 0) {
            std::cout << "line: " << __LINE__ <<" Creation of INET socket Failed" << std::endl;
            return(-1);
        }
    }

    handle(channel);
    connected_client(noor::NetInterface::client_connection::Disconnected);

    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << " Error: Could not set reuse address option on INET socket!" << std::endl;
        ::close(handle());
        connected_client().erase(handle());
        handle(-1);
        return(-1);
    }
    
    auto rc = ::connect(channel, (struct sockaddr *)&inet_server(), len);
    if(rc < 0) {
        if(errno == EINPROGRESS) {    
            //std::cout << "line: " << __LINE__ << " Connection is in-progress: "<< std::endl;
            connected_client(noor::NetInterface::client_connection::Inprogress);
            return(0);

        } else if(errno == ECONNREFUSED) {
            //Server is not strated yet
            std::cout << "line: " << __LINE__ << " Connect is refused errno: "<< std::strerror(errno) << std::endl;
            ::close(handle());
            connected_client().erase(handle());
            handle(-1);
            return(-1);

        } else {
            std::cout << "line: " << __LINE__ << " Connect is failed errno: "<< std::strerror(errno) << std::endl;
            ::close(handle());
            connected_client().erase(handle());
            handle(-1);
            return(-1);
        }
    } else {
        connected_client(noor::NetInterface::client_connection::Connected);
    }

    return(0);
}

/**
 * @brief 
 * 
 * @param IP 
 * @param PORT 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::udp_client(const std::string& IP, std::uint16_t PORT) {
    // UDP Client .... 
    bzero(&m_inet_server, sizeof(m_inet_server));
    m_inet_server.sin_family = AF_INET;
    m_inet_server.sin_port = htons(PORT);
    m_inet_server.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_inet_server.sin_zero, 0, sizeof(m_inet_server.sin_zero));

    std::int32_t channel = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(channel < 0) {
        std::cout << "line: " << __LINE__ <<" Creation of INET socket Failed" << std::endl;
        return(-1);
    }
    handle(channel);
    
    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << " Error: Could not set reuse address option on INET socket!" << std::endl;
        ::close(handle());
        handle(-1);
        return(-1);
    }

    return(0);
}

/**
 * @brief 
 * 
 * @param PATH 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::uds_client(const std::string& PATH) {
    std::int32_t channel = -1;
    /* Set up the address we're going to bind to. */
    bzero(&m_un_server, sizeof(m_un_server));
    m_un_server.sun_family = PF_UNIX;
    strncpy(m_un_server.sun_path, PATH.c_str(), sizeof(m_un_server.sun_path) -1);
    std::size_t len = sizeof(struct sockaddr_un);

    channel = ::socket(PF_UNIX, SOCK_STREAM/*|SOCK_NONBLOCK*/, 0);
    if(channel < 0) {
        std::cout << "line: "<<__LINE__ << "Creation of Unix socket Failed" << std::endl;
        return(-1);
    }

    handle(channel);
    connected_client(noor::NetInterface::client_connection::Disconnected);
    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << "Error: Could not set reuse address option on unix socket!" << std::endl;
        ::close(handle());
        handle(-1);
        return(-1);
    }

    auto rc = ::connect(channel, reinterpret_cast< struct sockaddr *>(&un_server()), len);
    if(rc == -1) {
        std::cout << __FILE__ <<":"<<__LINE__ <<"Connect is failed errno: "<< std::strerror(errno) << std::endl;
        ::close(handle());
        return(-1);
    }

    connected_client(noor::NetInterface::client_connection::Connected);
    return(0);
}

/**
 * @brief 
 * 
 * @return noor::NetInterface::emp 
 */
noor::NetInterface::emp noor::NetInterface::uds_rx() {
    std::uint16_t command;
    std::uint16_t message_id;
    std::uint32_t payload_size;
    std::uint16_t type;
    std::string response;
    std::array<char, 16> arr; 
    std::uint8_t EMP_HDR_SIZE = 8;
    arr.fill(0);

    auto len = recv(handle(), arr.data(), EMP_HDR_SIZE, 0);
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
            len = recv(handle(), (void *)(payload.get() + offset), (size_t)(payload_size - offset), 0);
            if(len < 0) {
                break;
            }
            offset += len;
        } while(offset != payload_size);

        if(offset == payload_size) {
            std::string ss((char *)payload.get(), payload_size);
            std::cout << "Payload: " << ss << std::endl;
            emp res;
            res.m_type = type;
            res.m_command = command;
            res.m_message_id = message_id;
            res.m_response_length = payload_size;
            res.m_response = ss;
            return(res);
        }
    }
    return(emp {});
}

/**
 * @brief 
 * 
 * @param channel 
 * @param data 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::tcp_rx(std::int32_t channel, std::string& data) {
    std::array<char, 8> arr;
    arr.fill(0);
    std::int32_t len = -1;
    //read 4 bytes - the payload length
    len = recv(channel, arr.data(), sizeof(std::int32_t), 0);
    if(!len) {
        std::cout << "line: " << __LINE__ << " closed" << std::endl;
        return(std::string().length());
    } else if(len > 0) {
        //std::cout << "line: " << __LINE__ << " len: " << len << std::endl;
        std::uint32_t payload_len; 
        std::istringstream istrstr;
        istrstr.rdbuf()->pubsetbuf(arr.data(), len);
        istrstr.read(reinterpret_cast<char *>(&payload_len), sizeof(payload_len));
        std::int32_t offset = 0;
        payload_len = ntohl(payload_len);
        //std::cout << "line: " << __LINE__ << " tcp payload length: " << payload_len << std::endl;

        std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
        do {
            len = recv(channel, (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
            if(len < 0) {
                offset = len;
                break;
            }
            offset += len;
        } while(offset != payload_len);
                
        if(offset == payload_len) {
            std::string ss((char *)payload.get(), payload_len);
            //std::cout <<"line: "<< __LINE__ << " From TCP Client Received: " << ss << std::endl;
            data = ss;
            return(payload_len);
        }
    }

    return(std::string().length());

}

/**
 * @brief 
 * 
 * @param data 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::tcp_rx(std::string& data) {
    std::array<char, 8> arr;
    arr.fill(0);
    std::int32_t len = -1;
    //read 4 bytes - the payload length
    len = recv(handle(), arr.data(), sizeof(std::int32_t), 0);
    if(!len) {
        std::cout << "line: " << __LINE__ << " closed" << std::endl;
        return(std::string().length());
    } else if(len > 0) {
        std::cout << "line: " << __LINE__ << " len: " << len << std::endl;
        std::uint32_t payload_len; 
        std::istringstream istrstr;
        istrstr.rdbuf()->pubsetbuf(arr.data(), len);
        istrstr.read(reinterpret_cast<char *>(&payload_len), sizeof(payload_len));
        std::int32_t offset = 0;
        payload_len = ntohl(payload_len);
        std::cout << "line: " << __LINE__ << " tcp payload length: " << payload_len << std::endl;

        std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
        do {
            len = recv(handle(), (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
            if(len < 0) {
                offset = len;
                break;
            }
            offset += len;
        } while(offset != payload_len);
                
        if(offset == payload_len) {
            std::string ss((char *)payload.get(), payload_len);
            std::cout <<"line: "<< __LINE__ << " From TCP Client Received: " << ss << std::endl;
            data = ss;
            return(payload_len);
        }
    }

    return(std::string().length());
}

std::string noor::NetInterface::get_contentType(std::string ext)
{
    std::string cntType("");
    /* get the extension now for content-type */
    if(!ext.compare("woff")) {
      cntType = "font/woff";
    } else if(!ext.compare("woff2")) {
      cntType = "font/woff2";
    } else if(!ext.compare("ttf")) {
      cntType = "font/ttf";
    } else if(!ext.compare("otf")) {
      cntType = "font/otf";
    } else if(!ext.compare("css")) {
      cntType = "text/css";
    } else if(!ext.compare("js")) {
      cntType = "text/javascript";
    } else if(!ext.compare("eot")) {
      cntType = "application/vnd.ms-fontobject";
    } else if(!ext.compare("html")) {
      cntType = "text/html";
    } else if(!ext.compare("svg")) {
      cntType = "image/svg+xml";
    } else if(!ext.compare("gif")) {
      cntType ="image/gif";
    } else if(!ext.compare("png")) {
      cntType = "image/png";
    } else if(!ext.compare("ico")) {
      cntType = "image/vnd.microsoft.icon";
    } else if(!ext.compare("jpg")) {
      cntType = "image/jpeg";
    } else if(!ext.compare("json")) {
      cntType = "application/json";
    } else {
      cntType = "text/html";
    }
    return(cntType);
}


std::string noor::NetInterface::buildHttpResponseOK(Http& http, std::string body, std::string contentType)
{
    std::stringstream ss("");

    ss << "HTTP/1.1 200 OK\r\n"
       << "Connection: "
       << http.value("Connection")
       << "\r\n"
       << "Host: "
       << http.value("Host")
       << "\r\n"
       << "Access-Control-Allow-Origin: *\r\n";

    if(body.length()) {
        ss << "Content-Length: "
           << body.length()
           << "\r\n"
           << "Content-Type: "
           << contentType
           <<"\r\n"
           << "\r\n"
           << body;

    } else {
        ss << "Content-Length: 0\r\n";
    }
    return(ss.str());
}

std::string noor::NetInterface::buildHttpRedirectResponse(Http& http, std::string rsp_body) {
    std::stringstream ss("");
    if(!rsp_body.length()) {
        rsp_body.assign("<html><title></title><head></head><body><h2>Redirecting to http://10.20.129.111</h2></body></html>");
    }

    ss << "HTTP/1.1 301 FOUND\r\n"
       << "Host: " << http.value("Host") << "\r\n"
       << "Connection: " << http.value("Connection") << "\r\n"
       << "Content-Type: text/html" << "\r\n"
       << "Content-Length: " << rsp_body.length() << "\r\n";
    
    if(!http.value("Origin").length()) {
        ss << "Access-Control-Allow-Origin: *\r\n";
    } else {
        ss << "Access-Control-Allow-Origin: "
           << http.value("Origin")
           << "\r\n";
    }

    ss << "\r\n"
       << rsp_body;

    return(ss.str());
}

std::string noor::NetInterface::buildHttpResponse(Http& http, const std::string& rsp_body) {
    std::stringstream ss("");
    ss << "HTTP/1.1 200 OK\r\n"
       << "Host: " << http.value("Host") << "\r\n"
       << "Connection: " << http.value("Connection") << "\r\n"
       << "Content-Type: application/json" << "\r\n";

    if(!http.value("Origin").length()) {
        ss << "Access-Control-Allow-Origin: *\r\n";
    } else {
        ss << "Access-Control-Allow-Origin: "
           << http.value("Origin")
           << "\r\n";
    }

    ss << "Content-Length: " << rsp_body.length() << "\r\n"
       << "\r\n"
       << rsp_body;

    return(ss.str());
}

std::string noor::NetInterface::handleOptionsMethod(Http& http) {
    std::stringstream http_header("");
    http_header << "HTTP/1.1 200 OK\r\n";
    http_header << "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n";
    http_header << "Access-Control-Allow-Headers: DNT, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Range\r\n";
    http_header << "Access-Control-Max-Age: 1728000\r\n";

    if(!http.value("Origin").length()) {
        http_header << "Access-Control-Allow-Origin: *\r\n";
    } else {
        http_header << "Access-Control-Allow-Origin: "
           << http.value("Origin")
           << "\r\n";
    }
    
    http_header << "Content-Type: text/plain; charset=utf-8\r\n";
    http_header << "Content-Length: 0\r\n";
    http_header << "\r\n";

    return(http_header.str());
}
std::string noor::NetInterface::handleGetMethod(Http& http) {

    std::stringstream ss("");
    if(!http.uri().compare(0, 20, " /api/v1/device/list")) {
        //Provide the device's list to Webclient.
        if(!noor::CommonResponse::instance().response().empty()) {
            ss << "[";
            std::for_each(noor::CommonResponse::instance().response().begin(), noor::CommonResponse::instance().response().end(), [&](const auto& ent) {
                ss << "[";
                std::for_each(ent.second.begin(), ent.second.end(), [&](const auto & elm) {
                    ss << elm << ",";
                });
                //get rid of last ',' from above array now.
                ss.seekp(-1, std::ios_base::end);
                ss << "],";
            });
            //get rid of last ','.
            ss.seekp(-1, std::ios_base::end);
            ss << "]";
        }

        auto rsp = buildHttpResponse(http, ss.str());
        return(rsp);

    } else if(!http.uri().compare(0, 17, "/api/v1/device/ui")) {
        return(buildHttpRedirectResponse(http));

    } else if((!http.uri().compare(0, 7, "/webui/"))) {
        /* build the file name now */
        std::string fileName("");
        std::string ext("");

        std::size_t found = http.uri().find_last_of(".");
        if(found != std::string::npos) {
          ext = http.uri().substr((found + 1), (http.uri().length() - found));
          fileName = http.uri().substr(6, (http.uri().length() - 6));
          std::string newFile = "../webgui/webui/" + fileName;
          /* Open the index.html file and send it to web browser. */
          std::ifstream ifs(newFile.c_str());
          std::stringstream ss("");

          if(ifs.is_open()) {
              std::string cntType("");
              cntType = get_contentType(ext); 

              ss << ifs.rdbuf();
              ifs.close();
              return(buildHttpResponseOK(http, ss.str(), cntType));
          }
        }
    } else if(!http.uri().compare(0, 8, "/assets/")) {
        /* build the file name now */
        std::string fileName("");
        std::string ext("");

        std::size_t found = http.uri().find_last_of(".");
        if(found != std::string::npos) {
          ext = http.uri().substr((found + 1), (http.uri().length() - found));
          std::string newFile = "../webgui/swi" + http.uri();
          /* Open the index.html file and send it to web browser. */
          std::ifstream ifs(newFile.c_str(), std::ios::binary);
          std::stringstream ss("");
          std::string cntType("");

          if(ifs.is_open()) {

              cntType = get_contentType(ext);
              ss << ifs.rdbuf();
              ifs.close();

              return(buildHttpResponseOK(http, ss.str(), cntType));
          }
        }

    } else if((!http.uri().compare(0, 7, "/swi/"))) {
        std::string newFile = "../webgui/swi/index.html";
        /* Open the index.html file and send it to web browser. */
        std::ifstream ifs(newFile.c_str(), std::ios::binary);
        std::stringstream ss("");
        std::string cntType("");

        if(ifs.is_open()) {
            cntType = "text/html";
            ss << ifs.rdbuf();
            ifs.close();

            return(buildHttpResponseOK(http, ss.str(), cntType));
        }
    } else if(!http.uri().compare(0, 2, " /")) {
        std::cout <<"line: " << __LINE__ << " processing index.html file " << std::endl;
        std::string newFile = "../webgui/swi/index.html";
        /* Open the index.html file and send it to web browser. */
        std::ifstream ifs(newFile.c_str(), std::ios::binary);
        std::stringstream ss("");
        std::string cntType("");

        if(ifs.is_open()) {
            cntType = "text/html";
            ss << ifs.rdbuf();
            ifs.close();

            return(buildHttpResponseOK(http, ss.str(), cntType));
        }
    }

    return(std::string());
}

std::string noor::NetInterface::process_web_request(const std::string& req) {
    Http http(req);
    if(!http.method().compare("GET")) {
        //handleGetRequest()
        auto rsp_body = handleGetMethod(http);
        return(rsp_body);
        /*
        if(rsp_body.length()) {
            auto rsp = buildHttpResponse(http, rsp_body);
            return(rsp);
        }*/
    }
    else if(!http.method().compare("POST")) {
        //handlePostMethod()
    }
    else if(!http.method().compare("PUT")) {
        //handlePutMethod()
    }
    else if(!http.method().compare("OPTIONS")) {
        return(handleOptionsMethod(http));
    }
    else if(!http.method().compare("DELETE")) {
        //handleDeleteMethod()
    }
    else {
        //Error
    }
    return(std::string());
}

/**
 * @brief 
 * 
 * @param http 
 * @return std::string 
 */
std::string noor::NetInterface::build_web_response(Http& http) {
    //Build HTTP Response
    std::cout << "URI: " << http.uri() << " method: " << http.method() << std::endl;
    std::stringstream ss("");
    std::string payload("<html><title></title><head></head><body><h2>Redirecting to http://10.20.129.111</h2></body></html>");
    ss << "HTTP/1.1 302 Found\r\n"
       //<< "Location: https://192.168.1.1:443\r\n"
       << "Location: http://10.20.129.111\r\n"
       << "Content-length: " << payload.length() << "\r\n"
       << "Connection: close\r\n"
       //<< "Cookie: unity_token=IC3wWl66tT3XrqO88iLBSxCYbuxhPvGz; unity_login=admin; last_connection={\"success_last\":\"Sat Apr  8 03:47:22 2023\",\"success_from\":\"192.168.1.100\",\"failures\":0}" 
       << "Cookie: " << http.value("Cookies")
       << "\r\n\r\n"
       << payload;

    std::cout << "The Web Response is " << ss.str() << std::endl;
    return(ss.str());
}

/**
 * @brief 
 * 
 * @param channel 
 * @param data 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::web_rx(std::int32_t channel, std::string& data) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << " handle:" << handle() <<std::endl;
    std::array<char, 2048> arr;
    arr.fill(0);
    std::int32_t len = -1;
    len = recv(channel, arr.data(), arr.size(), 0);
    if(!len) {
        std::cout << "function: "<<__FUNCTION__ << " line: " << __LINE__ << " closed" << std::endl;
    } else if(len > 0) {
        std::string ss(arr.data(), len);
        std::cout << "HTTP: " << std::endl << ss << std::endl;
        Http http(ss);
        std::cout << "line: " << __LINE__ << " URI: "   << http.uri()    << std::endl;
        std::cout << "line: " << __LINE__ << " Header " << http.header() << std::endl;
        std::cout << "line: " << __LINE__ << " Body "   << http.body()   << std::endl;
        std::uint32_t offset = 0;
        auto cl = http.value("Content-Length");
        size_t payload_len = 0;

        if(!cl.length()) {
            std::cout << "line: " << __LINE__ << " Content-Length is not present" << std::endl;
            data = ss;
            return(data.length());

        } else {
            std::cout << "function: "<< __FUNCTION__ << " line: " << __LINE__ <<" value of Content-Length " << cl << std::endl;
            payload_len = std::stoi(cl);
            if(len == (payload_len + http.header().length())) {
                //We have received the full HTTP packet
                data = ss;
                return(data.length());

            } else {
                //compute the effective length
                payload_len = (std::stoi(cl) + http.header().length() - len);
                std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
                std::int32_t tmp_len = 0;
                do {
                    tmp_len = recv(channel, (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
                    if(tmp_len < 0) {
                        offset = len;
                        break;
                    }
                    offset += tmp_len;
                    
                } while(offset != payload_len);

                if(offset == payload_len) {
                    std::string header(arr.data(), len);
                    std::string ss((char *)payload.get(), payload_len);
                    std::string request = header + ss;
                    std::cout << "function: "<<__FUNCTION__ <<" line: " <<__LINE__ << " From Web Client Received: " << request << std::endl;
                    data = ss;
                    return(data.length());
                }
            }
        }
    }
    return(std::string().length());
}

/**
 * @brief 
 * 
 * @param data 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::web_rx(std::string& data) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << " handle:" << handle() <<std::endl;
    std::array<char, 2048> arr;
    arr.fill(0);
    std::int32_t len = -1;
    len = recv(handle(), arr.data(), arr.size(), 0);
    if(!len) {
        std::cout << "function: "<<__FUNCTION__ << " line: " << __LINE__ << " closed" << std::endl;
    } else if(len > 0) {
        std::string ss(arr.data(), len);
        std::cout << "HTTP: " << std::endl << ss << std::endl;
        Http http(ss);
        std::cout << "line: " << __LINE__ << " URI: "   << http.uri()    << std::endl;
        std::cout << "line: " << __LINE__ << " Header " << http.header() << std::endl;
        std::cout << "line: " << __LINE__ << " Body "   << http.body()   << std::endl;
        std::uint32_t offset = 0;
        auto cl = http.value("Content-Length");
        size_t payload_len = 0;

        if(!cl.length()) {
            std::cout << "line: " << __LINE__ << " Content-Length is not present" << std::endl;
            data = ss;
            return(data.length());

        } else {
            std::cout << "function: "<< __FUNCTION__ << " line: " << __LINE__ <<" value of Content-Length " << cl << std::endl;
            payload_len = std::stoi(cl);
            if(len == (payload_len + http.header().length())) {
                //We have received the full HTTP packet
                data = ss;
                return(data.length());

            } else {
                //compute the effective length
                payload_len = (std::stoi(cl) + http.header().length() - len);
                std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
                std::int32_t tmp_len = 0;
                do {
                    tmp_len = recv(handle(), (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
                    if(tmp_len < 0) {
                        offset = len;
                        break;
                    }
                    offset += tmp_len;
                    
                } while(offset != payload_len);

                if(offset == payload_len) {
                    std::string header(arr.data(), len);
                    std::string ss((char *)payload.get(), payload_len);
                    std::string request = header + ss;
                    std::cout << "function: "<<__FUNCTION__ <<" line: " <<__LINE__ << " From Web Client Received: " << request << std::endl;
                    data = ss;
                    return(data.length());
                }
            }
        }
    }
    return(std::string().length());  
}

/**
 * @brief 
 * 
 * @param data 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::udp_rx(std::string& data) {
    std::array<char, 8> arr;
    arr.fill(0);
    std::int32_t len = -1;
    struct sockaddr_in peer;
    socklen_t peer_addr_len = sizeof(peer);

    len = recvfrom(handle(), arr.data(), sizeof(std::int32_t), MSG_PEEK, (struct sockaddr *)&peer, &peer_addr_len);
    if(!len) {
        std::cout << "line: " << __LINE__ << " closed" << std::endl;
        return(std::string().length());

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
            len = recvfrom(handle(), (void *)(payload.get() + offset), (size_t)(payload_len - offset), MSG_WAITALL, (struct sockaddr *)&peer, &peer_addr_len);
            if(len < 0) {
                offset = len;
                break;
            }
            offset += len;
        } while(offset != payload_len);
                
        if(offset> 0 && offset == payload_len) {
            std::string ss((char *)payload.get() + 4, payload_len-4);
            //std::cout << "line: "<< __LINE__ << " From UDP Client Received: " << ss << std::endl;
            data = ss;
            return(ss.length());
        }
    }
    return(std::string().length());
}

/**
 * @brief 
 * 
 * @param IP 
 * @param PORT 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::tcp_server(const std::string& IP, std::uint16_t PORT) {
   /* Set up the address we're going to bind to. */
    bzero(&m_inet_server, sizeof(m_inet_server));
    m_inet_server.sin_family = AF_INET;
    m_inet_server.sin_port = htons(PORT);
    if(!IP.compare("127.0.0.1")) {
        m_inet_server.sin_addr.s_addr = INADDR_ANY;    
    } else {
        m_inet_server.sin_addr.s_addr = inet_addr(IP.c_str());
    }
    memset(m_inet_server.sin_zero, 0, sizeof(m_inet_server.sin_zero));
    auto len = sizeof(m_inet_server);

    std::int32_t channel = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(channel < 0) {
        std::cout << "line: " << __LINE__ << " Creation of INET socket Failed" << std::endl;
        return(-1);
    }

    handle(channel);
    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << "Error: Could not set reuse address option on INET socket!" << std::endl;
        ::close(handle());
        handle(-1);
        return(-1);
    }
    auto ret = ::bind(channel, (struct sockaddr *)&m_inet_server, sizeof(m_inet_server));
    if(ret < 0) {
        std::cout <<"line: " << __LINE__ << " bind to IP: " << IP << " PORT: " << PORT << " Failed" <<std::endl;
        ::close(handle());
        handle(-1);
	    return(-1);
    }

    if(listen(channel, 10) < 0) {
        std::cout << "line: " << __LINE__ << " listen to channel: " << channel << " Failed" <<std::endl;
        ::close(handle());
        handle(-1);
	    return(-1);
    }

    return(0); 
}

/**
 * @brief 
 * 
 * @param IP 
 * @param PORT 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::udp_server(const std::string& IP, std::uint16_t PORT) {
    // UDP Server .... 
    /* Set up the address we're going to bind to. */
    bzero(&m_inet_server, sizeof(m_inet_server));
    m_inet_server.sin_family = AF_INET;
    m_inet_server.sin_port = htons(PORT);
    m_inet_server.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_inet_server.sin_zero, 0, sizeof(m_inet_server.sin_zero));
    auto len = sizeof(m_inet_server);

    std::int32_t channel = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(channel < 0) {
        std::cout << "line: " << __LINE__ <<" Creation of INET socket Failed" << std::endl;
        return(-1);
    }

    handle(channel);
    
    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "line: " << __LINE__ << " Error: Could not set reuse address option on INET socket!" << std::endl;
        ::close(handle());
        handle(-1);
        return(-1);
    }

    auto ret = ::bind(channel, (struct sockaddr *)&inet_server(), len);
    if(ret < 0) {
        std::cout << "line: "<< __LINE__ << " bind to UDP protocol failed" << std::endl;
        ::close(handle());
        handle(-1);
        return(-1);
    }
    return(0);
}

/**
 * @brief 
 * 
 * @param IP 
 * @param PORT 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::web_server(const std::string& IP, std::uint16_t PORT) {
    /* Set up the address we're going to bind to. */
    bzero(&m_inet_server, sizeof(m_inet_server));
    m_inet_server.sin_family = AF_INET;
    m_inet_server.sin_port = htons(PORT);

    if(!IP.compare("127.0.0.1")) {
        m_inet_server.sin_addr.s_addr = INADDR_ANY;    
    } else {
        m_inet_server.sin_addr.s_addr = inet_addr(IP.c_str());
    }

    memset(m_inet_server.sin_zero, 0, sizeof(m_inet_server.sin_zero));
    auto len = sizeof(m_inet_server);

    std::int32_t channel = ::socket(AF_INET, SOCK_STREAM, 0);
    if(channel < 0) {
        std::cout << "Creation of INET socket Failed" << std::endl;
        return(-1);
    }

    handle(channel);
    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "Error: Could not set reuse address option on INET socket!" << std::endl;
        ::close(handle());
        handle(-1);
        return(-1);
    }
    auto ret = ::bind(channel, (struct sockaddr *)&inet_server(), len);
    if(ret < 0) {
        std::cout << "line: "<< __LINE__ << " bind to IP: " << IP << " PORT: " << PORT << " Failed" <<std::endl;
        ::close(handle());
        handle(-1);
	return(-1);
    }

    if(listen(channel, 10) < 0) {
        std::cout << "line: " << __LINE__ << " listen to channel: " << channel << " Failed" <<std::endl;
        ::close(handle());
        handle(-1);
	return(-1);
    }

    return(0); 
}

/**
 * @brief 
 * 
 * @param channel 
 * @param req 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::web_tx(std::int32_t channel, const std::string& req) {
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

/**
 * @brief 
 * 
 * @param req 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::web_tx(const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;

    do {
        len = send(handle(), req.data() + offset, req_len - offset, 0);
        if(len < 0) {
            offset = len;
            break;
        } 
        offset += len;
    } while(offset != req_len);

    return(offset);
}

/**
 * @brief 
 * 
 * @param req 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::udp_tx(const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t payload_len = req.length();
    std::int32_t len = -1;
    auto total_len = htonl(payload_len);
    std::stringstream data("");
    data.write(reinterpret_cast <char *>(&total_len), sizeof(std::int32_t));
    data << req;
    payload_len = data.str().length();

    do {
        len = sendto(handle(), data.str().data() + offset, payload_len - offset, 0, (struct sockaddr *)&m_inet_server, sizeof(m_inet_server));
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

/**
 * @brief 
 * 
 * @param req 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::uds_tx(const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;

    do {
        len = send(handle(), req.data() + offset, req_len - offset, 0);
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

/**
 * @brief 
 * 
 * @param req 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::tcp_tx(const std::string& req) {
    std::int32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;
    auto payload_len = htonl(req_len);
    std::stringstream data("");
    data.write (reinterpret_cast <char *>(&payload_len), sizeof(std::int32_t));
    data << req;
    req_len = data.str().length();
    do {
        len = send(handle(), data.str().data() + offset, req_len - offset, 0);
        if(len < 0) {
            offset = len;
            break;
        }
        offset += len;
    } while(offset != req_len);

    if(offset == req_len) {
        std::cout <<"line: "<< __LINE__ << " Request sent to TCP Server successfully: req_len:" << req_len << std::endl;
    }
    return(offset);
}      

/**
 * @brief 
 * 
 * @param timeout_in_ms 
 * @param intf_list 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::start_client(std::uint32_t timeout_in_ms, std::vector<std::tuple<std::unique_ptr<NetInterface>, socket_type>> intf_list) {
    int conns  = -1;
    fd_set fdList;
    fd_set fdWrite;
    
    while (1) {

        struct timeval to;
        to.tv_sec = timeout_in_ms / 1000;
        to.tv_usec = timeout_in_ms % 1000;

        FD_ZERO(&fdList);
        FD_ZERO(&fdWrite);
        
        for(auto& [inst, type]: intf_list) {
            auto channel = inst->handle();

            if(channel > 0 && noor::NetInterface::socket_type::UNIX == type) {
                FD_SET(channel, &fdList);

            } else if(channel > 0 && noor::NetInterface::socket_type::TCP_ASYNC == type) {
                if(inst->connected_client(channel) == noor::NetInterface::client_connection::Connected) {
                    //std::cout << "line: " << __LINE__ << " function: " << __FUNCTION__ << " handle: " << channel << "connected " << std::endl;
                    FD_SET(channel, &fdList);
                } else if(inst->connected_client(inst->handle()) == noor::NetInterface::client_connection::Inprogress) {
                    //std::cout << "line: " << __LINE__ << " function: " << __FUNCTION__ << " handle: " << channel << "fdWrite " << std::endl;
                    FD_SET(channel, &fdWrite);
                }

            } else if(channel > 0 && noor::NetInterface::socket_type::UDP == type) {
                FD_SET(channel, &fdList);

            } else if(channel > 0 && noor::NetInterface::socket_type::UDP_ASYNC == type) {
                FD_SET(channel, &fdList);

            } else if(channel > 0 && noor::NetInterface::socket_type::TCP == type) {
                if(inst->connected_client(channel) == noor::NetInterface::client_connection::Connected) {
                    FD_SET(channel, &fdList);
                }
            }
        }

        conns = ::select(FD_SETSIZE, (fd_set *)&fdList, (fd_set *)&fdWrite, (fd_set *)NULL, (struct timeval *)&to);
        
        if(conns > 0) {

            for(auto& [inst, type]: intf_list) {
                auto channel = inst->handle();

                // Received on Unix Socket
                if(channel > 0 && type == noor::NetInterface::socket_type::UNIX && FD_ISSET(channel, &fdList)) {
                    //Received response from Data store
                    std::string request("");
                    std::cout << "From DS line: " << __LINE__<<" Response received " << std::endl;
                    auto req = inst->uds_rx();
                    if(!req.m_response.length()) {
                        ::close(channel);
                        inst->connected_client().erase(channel);
                        inst->handle(-1);
                        std::cout <<"line: " << __LINE__ << " Data store is down" << std::endl;
                        exit(0);
                    } else {
                        std::cout << "line: " << __LINE__ << " Caching the response" << std::endl;
                        //Cache the response and will be sent later when TCP connection is established or upon timed out
                        inst->update_response_to_cache(req.m_message_id, req.m_response);
                    }
                }
                //Received on UDP Socket
                if(channel > 0 && type == noor::NetInterface::socket_type::UDP && FD_ISSET(channel, &fdList)) {
                    //From UDP Server
                    std::string ret("");
                    //auto ret = udp_rx(udp_client_fd());
                    std::cout << "line: " << __LINE__ << " Xreating issue " << std::endl;
                    if(ret.length()) {
                        //Got Response from UDP client
                    }
                }
                //The TCP client might be connected
                if(channel > 0 && type == noor::NetInterface::socket_type::TCP_ASYNC && FD_ISSET(channel, &fdWrite)) {
                    //TCP connection established successfully.
                    //Push changes if any now
                    //When the connection establishment (for non-blocking socket) encounters an error, the descriptor becomes both readable and writable (p. 530 of TCPv2).
                    socklen_t optlen;
                    std::int32_t optval = -1;
                    optlen = sizeof (optval);
                    if(!getsockopt(channel, SOL_SOCKET, SO_ERROR, &optval, &optlen)) {
                        struct sockaddr_in peer;
                        socklen_t sock_len = sizeof(peer);
                        memset(&peer, 0, sizeof(peer));
                        auto ret = getpeername(channel, (struct sockaddr *)&peer, &sock_len);
                        if(ret < 0 && errno == ENOTCONN) {
                            ::close(channel);
                            inst->connected_client().erase(channel);
                            inst->handle(-1);
                        } else if(!ret) {
                            //TCP Client is connected 
                            inst->connected_client(noor::NetInterface::client_connection::Connected);
                            FD_CLR(channel, &fdWrite);
                            FD_ZERO(&fdWrite);
                            std::cout << "line: " << __LINE__ << " Connected to server handle: " << inst->handle() << std::endl;

                            auto it = std::find_if(intf_list.begin(), intf_list.end(), [&](const auto& ent) {
                                auto type = std::get<1>(ent);
                                return(noor::NetInterface::socket_type::UNIX == type);
                            });

                            if(it!= intf_list.end() && !std::get<0>(*it)->response_cache().empty()) {
                                for(const auto& ent: std::get<0>(*it)->response_cache()) {
                                    std::string payload = std::get<cache_element::RESPONSE>(ent);

                                    //don't push to TCP server If response is awaited.
                                    if(payload.compare("default")) {
                                        std::uint32_t payload_len = payload.length();
                                        payload_len = htonl(payload_len);
                                        std::stringstream data("");
                                        data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
                                        data << payload;
                                        auto ret = inst->tcp_tx(payload);
                                        std::cout << "line: " << __LINE__ << " sent to TCP Server data-length:"<< ret << std::endl;
                                    }
                                }
                            }
                        }
                    }
                }
                if(channel > 0 && type == noor::NetInterface::socket_type::TCP_ASYNC && FD_ISSET(channel, &fdList)) {
                    //From TCP Server
                    std::string request("");
                    auto req = inst->tcp_rx(request);
                    std::cout << "line: "<< __LINE__ << " Response received from TCP Server length:" << req << std::endl;
                    if(!req && inst->connected_client(channel) == noor::NetInterface::client_connection::Connected) {
                        ::close(channel);
                        inst->connected_client().erase(channel);
                        inst->handle(-1);
                    } else {
                        //Got from TCP server 
                        std::cout <<"line: " << __LINE__ << "Received from TCP server length: " << req << std::endl;
                    }
                }
            }
        }
        else if(!conns) {
            //time out happens
            auto it = std::find_if(intf_list.begin(), intf_list.end(), [&](auto& ent) {
                auto type = std::get<1>(ent);
                return(type == noor::NetInterface::socket_type::TCP_ASYNC);
            });
            if((it != intf_list.end()) && (std::get<0>(*it)->handle() < 0) && (!std::get<0>(*it)->get_config().at("protocol").compare("tcp"))) {
                std::get<0>(*it)->tcp_client_async(std::get<0>(*it)->get_config().at("server-ip"), std::stoi(std::get<0>(*it)->get_config().at("server-port")));
            }

            it = std::find_if(intf_list.begin(), intf_list.end(), [&](auto& ent) {
                auto type = std::get<1>(ent);
                return(type == noor::NetInterface::socket_type::UDP);
            });

            if(it != intf_list.end()  && !std::get<0>(*it)->get_config().at("protocol").compare("udp")) {
                for(auto iter = std::get<0>(*it)->response_cache().begin(); iter != std::get<0>(*it)->response_cache().end(); ++iter) {
                    std::string payload = std::get<4>(*iter);
                    //don't push to TCP server If response is awaited.
                    if(payload.compare("default")) {
                        if(std::get<0>(*it)->udp_tx(payload) > 0) {
                            //Sent successfully
                            auto channel = std::get<0>(*it)->handle();
                            iter = std::get<0>(*it)->response_cache().erase(iter);
                        }
                    }
                }
            }
        }
    } /* End of while loop */
}

/**
 * @brief 
 * 
 * @param timeout_in_ms 
 * @param intf_list 
 * @return * std::int32_t 
 */
std::int32_t noor::NetInterface::start_server(std::uint32_t timeout_in_ms, std::vector<std::tuple<std::unique_ptr<noor::NetInterface>, noor::NetInterface::socket_type>> intf_list) {
    int conns   = -1;
    fd_set readFd;

    while (1) {
        /* A timeout for 100ms*/ 
        struct timeval to;
        to.tv_sec = timeout_in_ms /1000;
        to.tv_usec = timeout_in_ms % 1000;
        FD_ZERO(&readFd);

        for(const auto& [inst, type]: intf_list) {

            if(noor::NetInterface::socket_type::WEB == type && inst->handle() > 0) {
                FD_SET(inst->handle(), &readFd);
            }
            
            if(noor::NetInterface::socket_type::TCP == type && inst->handle() > 0) {
                FD_SET(inst->handle(), &readFd);
            }

            if(noor::NetInterface::socket_type::UNIX == type && inst->handle() > 0) {
                FD_SET(inst->handle(), &readFd);
            }

            if(noor::NetInterface::socket_type::UDP == type && inst->handle() > 0) {
                FD_SET(inst->handle(), &readFd);
            }
            
            if(!inst->web_connections().empty()) {
                for(const auto& [key, value]: inst->web_connections()) {
                    FD_SET(std::get<0>(value), &readFd);    
                }
            }

            if(!inst->tcp_connections().empty()) {
                for(const auto& [key, value]: inst->tcp_connections()) {
                    FD_SET(std::get<0>(value), &readFd);    
                }
            }
        }

        conns = ::select(FD_SETSIZE, (fd_set *)&readFd, (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)&to);

        if(conns > 0) {
            for(const auto& [inst, type]: intf_list) {
                if(type == noor::NetInterface::socket_type::TCP && inst->handle() > 0 && FD_ISSET(inst->handle(), &readFd)) {
                    // accept a new connection 
                    struct sockaddr_in peer;
                    socklen_t peer_len = sizeof(peer);
                    auto newFd = ::accept(inst->handle(), (struct sockaddr *)&peer, &peer_len);
                    if(newFd > 0) {
                        std::string IP(inet_ntoa(peer.sin_addr));
                        inst->tcp_connections().insert(std::make_pair(newFd, std::make_tuple(newFd, IP, ntohs(peer.sin_port), 0, 0, 0)));
                        std::cout << "line: " << __LINE__ << " chnnel: " << newFd << " IP: " << IP <<" port:" << ntohs(peer.sin_port) << std::endl;
                    }
                }
                if(type == noor::NetInterface::socket_type::WEB && inst->handle() > 0 && FD_ISSET(inst->handle(), &readFd)) {
                    // accept a new connection 
                    struct sockaddr_in peer;
                    socklen_t peer_len = sizeof(peer);
                    auto newFd = ::accept(inst->handle(), (struct sockaddr *)&peer, &peer_len);
                    if(newFd > 0) {
                        std::string IP(inet_ntoa(peer.sin_addr));
                        inst->web_connections().insert(std::make_pair(newFd, std::make_tuple(newFd, IP, ntohs(peer.sin_port), 0, 0, 0)));
                        std::cout << "line: " << __LINE__ << " chnnel: " << newFd << " IP: " << IP <<" port:" << ntohs(peer.sin_port) << std::endl;
                    }
                }
                if(type == noor::NetInterface::socket_type::UNIX && inst->handle() > 0 && FD_ISSET(inst->handle(), &readFd)) {
                    // accept a new connection 
                    struct sockaddr_un peer;
                    socklen_t peer_len = sizeof(peer);
                    auto newFd = ::accept(inst->handle(), (struct sockaddr *)&peer, &peer_len);
                    if(newFd > 0) {
                        std::string IP(peer.sun_path);
                        inst->unix_connections().insert(std::make_pair(newFd, std::make_tuple(newFd, IP, 0, 0, 0, 0)));
                    }
                }
                if(type == noor::NetInterface::socket_type::UDP && inst->handle() > 0 && FD_ISSET(inst->handle(), &readFd)) {
                    std::string response("");
                    auto res = inst->udp_rx(response);
                    if(!res) {
                        std::cout << "line: " << __LINE__ << " Received from UDP Client " << std::endl;
                        std::cout << "line: " << __LINE__ << " Response: " << response;
                    }
                }
                
                if(!inst->tcp_connections().empty()) {
                    for(const auto &[key, value]: inst->tcp_connections()) {
                        auto channel = std::get<0>(value);
                        if(channel > 0 && FD_ISSET(channel, &readFd)) {
                            //From TCP Client
                            std::string request("");
                            std::cout << "line: "<< __LINE__ << " Response received from TCP client: " << std::endl;
                            auto req = inst->tcp_rx(channel, request);
                            if(!req) {
                                //client is closed now
                                std::cout << "line: " << __LINE__ << " req.length: " << request.length() <<std::endl; 
                                ::close(channel);
                                auto it = inst->tcp_connections().erase(channel);
                            } else {
                                std::cout << "line: " << __LINE__ << " Data TCP Server Received: " << request << std::endl;
                                noor::CommonResponse::instance().response(channel, request);
                            }
                        }
                    }
                }
                if(!inst->web_connections().empty()) {
                    for(const auto &[key, value]: inst->web_connections()) {
                        auto channel = std::get<0>(value);
                        if(channel > 0 && FD_ISSET(channel, &readFd)) {
                            //From Web Client 
                            std::string request("");
                            std::cout <<"line: " << __LINE__ << " Request from Web client received on channel "<< channel << std::endl;
                            auto req = inst->web_rx(channel, request);
                            if(!req) {
                                std::cout << "line: " << __LINE__ << " req.length: " << request.length() <<std::endl; 
                                //client is closed now 
                                ::close(channel);
                                auto it = inst->web_connections().erase(channel);
                            } else {
                                std::cout << "line: " << __LINE__ << " Data WEB Server Received: " << request << std::endl;
                                Http http(request);
                                //auto rsp = build_web_response(http);
                                auto rsp = process_web_request(request);
                                if(rsp.length()) {
                                    auto ret = web_tx(channel, rsp);
                                }
                            }
                        }
                    }
                }
                if(!inst->unix_connections().empty()) {
                    for(const auto &[key, value]: inst->web_connections()) {
                        auto channel = std::get<0>(value);
                        if(channel > 0 && FD_ISSET(channel, &readFd)) {
                            //From Web Client 
                            std::string request("");
                            std::cout <<"line: " << __LINE__ << " Request from Web client received on channel "<< channel << std::endl;
                            auto req = uds_rx();
                            if(!req.m_response.length()) {
                                //client is closed now 
                                ::close(channel);
                                auto it = inst->unix_connections().erase(channel);
                            }
                        }
                    }
                }
            }
        } /*conns > 0*/
    } /* End of while loop */
}

/**
 * @brief 
 * 
 * @param cmd_type 
 * @param cmd 
 * @param req 
 * @return std::string 
 */
std::string noor::NetInterface::serialise(noor::Uniimage::EMP_COMMAND_TYPE cmd_type, noor::Uniimage::EMP_COMMAND_ID cmd, const std::string& req) {
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

/**
 * @brief 
 * 
 * @param prefix 
 * @param fields 
 * @param filter 
 * @return std::string 
 */
std::string noor::NetInterface::packArguments(const std::string& prefix, std::vector<std::string> fields, std::vector<std::string> filter) {
    std::stringstream rsp("");
    std::string result("");

    if(prefix.empty()) {
        //This can't be empty
        return(std::string());
    } else {
	if(true == is_register_variable()) {
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

/**
 * @brief 
 * 
 * @param prefix 
 * @param fields 
 * @param filter 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::registerGetVariable(const std::string& prefix, std::vector<std::string> fields, std::vector<std::string> filter) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::RegisterGetVariable;
    is_register_variable(true); 
    std::string rsp = packArguments(prefix, fields, filter);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = uds_tx(data);
    std::string response("");
    add_element_to_cache({cmd_type, cmd, message_id(), prefix, response}); 
    is_register_variable(false);
    return(ret);

}

/**
 * @brief 
 * 
 * @param prefix 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::getSingleVariable(const std::string& prefix) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::SingleGetVariable;
    
    std::string rsp = packArguments(prefix);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = uds_tx(data); 
    std::string response("");
    add_element_to_cache({cmd_type, cmd, message_id(), prefix, response}); 
    
    return(ret);
}

/**
 * @brief 
 * 
 * @param prefix 
 * @param fields 
 * @param filter 
 * @return std::int32_t 
 */
std::int32_t noor::NetInterface::getVariable(const std::string& prefix, std::vector<std::string> fields, std::vector<std::string> filter) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::GetVariable;

    std::string rsp = packArguments(prefix, fields, filter);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = uds_tx(data);
    std::string response("");
    add_element_to_cache({cmd_type, cmd, message_id(), prefix, response});
    return(ret);
}

/**
 * @brief 
 * 
 * @param in 
 * @return std::int32_t 
 */
std::string TcpClient::onReceive(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(std::string());
}

std::int32_t TcpClient::onClose(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(0);
}

std::string UdpClient::onReceive(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(std::string());
}

std::int32_t UdpClient::onClose(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(0);
}

std::string UnixClient::onReceive(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(std::string());
}

std::int32_t UnixClient::onClose(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(0);
}

std::string TcpServer::onReceive(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(std::string());
}

std::int32_t TcpServer::onClose(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(0);
}

std::string UdpServer::onReceive(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(std::string());
}

std::int32_t UdpServer::onClose(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(0);
}

std::string WebServer::onReceive(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(std::string());
}

std::int32_t WebServer::onClose(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(0);
}

std::string UnixServer::onReceive(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(std::string());
}

std::int32_t UnixServer::onClose(std::string in) {
    std::cout << "line: " << __LINE__ << " " << __PRETTY_FUNCTION__ << std::endl;
    return(0);
}



std::uint32_t from_json_element_to_string(const std::string json_obj, const std::string key, std::string& str_out)
{

  bsoncxx::document::value doc_val = bsoncxx::from_json(json_obj.c_str());
  bsoncxx::document::view doc = doc_val.view();

  auto it = doc.find(key);
  if(it == doc.end()) {
    std::cout << "line: " << __LINE__ << "key: " << key;
    str_out.clear();
    return(1);    
  }

  bsoncxx::document::element elm_value = *it;
  if(elm_value && bsoncxx::type::k_utf8 == elm_value.type()) {
      std::string elm(elm_value.get_utf8().value.data(), elm_value.get_utf8().value.length());
      str_out.assign(elm);
  } else {
    str_out.clear();
  }
  
  return(0);
}

std::uint32_t from_json_array_to_map(const std::string json_obj, std::unordered_map<std::string, std::string>& out)
{
    bsoncxx::document::value doc_val = bsoncxx::from_json(json_obj.c_str());
    bsoncxx::document::view doc = doc_val.view();
    auto key="element";
    
    auto it = doc.find(key);
    if(it == doc.end()) {
        std::cout << "line: " << __LINE__ << " key: " << key << std::endl;
        return(1);    
    }

    bsoncxx::document::element elm_value = *it;

    if(elm_value && bsoncxx::type::k_array == elm_value.type()) {
        bsoncxx::array::view to(elm_value.get_array().value);
        std::cout << "line: " << __LINE__ << " document type is array" << std::endl;
        for(bsoncxx::array::element elm : to) {
          if(bsoncxx::type::k_document == elm.type()) {
            std::cout << "line: " << __LINE__ << " document type is document" << std::endl;
            auto doc = elm.get_document().value;
            auto it = doc.find("key");
            if(it != doc.end()) {
                std::cout << "line: " << __LINE__ << " value: " << doc["key"].get_utf8().value.data() << std::endl;
            }
          }
        }
    }
  
    return(0);
}


#endif /* __uniimage__cc__ */
