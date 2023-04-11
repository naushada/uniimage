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
    memset(m_tcp_server.sin_zero, 0, sizeof(m_web_server.sin_zero));
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
    bzero(&m_tcp_server, sizeof(m_tcp_server));
    m_tcp_server.sin_family = AF_INET;
    m_tcp_server.sin_port = htons(PORT);
    m_tcp_server.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_tcp_server.sin_zero, 0, sizeof(m_tcp_server.sin_zero));
    auto len = sizeof(m_tcp_server);

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
    auto ret = ::bind(channel, (struct sockaddr *)&m_tcp_server, sizeof(m_tcp_server));
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
    std::int32_t ret = ds_tx(uds_client_fd(), data);
    add_element(cmd_type, cmd, m_message_id, prefix); 
    m_is_reg_ds = false; 
    return(ret);

}

std::int32_t noor::Uniimage::getSingleVariable(const std::string& prefix) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::SingleGetVariable;
    
    std::string rsp = packArguments(prefix);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = ds_tx(uds_client_fd(), data); 
    add_element(cmd_type, cmd, m_message_id, prefix); 
    
    return(ret);
}

std::int32_t noor::Uniimage::getVariable(const std::string& prefix, std::vector<std::string> fields, std::vector<std::string> filter) {
    noor::Uniimage::EMP_COMMAND_TYPE cmd_type = noor::Uniimage::EMP_COMMAND_TYPE::Request;
    noor::Uniimage::EMP_COMMAND_ID cmd = noor::Uniimage::EMP_COMMAND_ID::GetVariable;

    std::string rsp = packArguments(prefix, fields, filter);
    std::string data = serialise(cmd_type, cmd, rsp);
    std::int32_t ret = ds_tx(uds_client_fd(), data);
     
    add_element(cmd_type, cmd, m_message_id, prefix);
    return(ret);
}

std::int32_t noor::Uniimage::tcp_tx(std::int32_t channel, const std::string& req) {
    std::uint32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;

    do {
        len = send(channel, req.data() + offset, req_len - offset, 0);
        if(len > 0) {
            offset += len;
            for(std::int32_t idx = 0; idx < 8; ++idx) {
                printf("%X ", req.c_str()[idx]);
            }
        }
    } while(offset != req_len);
    if(offset == req_len) {
        std::cout << "Request sent to TCP Server successfully" << std::endl;
    }
    return(offset);
}

std::int32_t noor::Uniimage::ds_tx(std::int32_t channel, const std::string& req) {
    std::uint32_t offset = 0;
    std::int32_t req_len = req.length();
    std::int32_t len = -1;

    do {
        len = send(channel, req.data() + offset, req_len - offset, 0);
        std::cout << "sent bytes: " << len << std::endl;
        if(len > 0) {
            offset += len;
            for(std::int32_t idx = 0; idx < 8; ++idx) {
                printf("%X ", req.c_str()[idx]);
            }
        }
    } while(offset != req_len);
    if(offset == req_len) {
        std::string ss(reinterpret_cast<const char *>(&req.c_str()[8]));
        std::cout << "Query pushed to DS ==> " << ss << std::endl;
    }
    return(offset);
}


std::string noor::Uniimage::tcp_rx(std::int32_t handle) {
    std::array<char, 8> arr;
    arr.fill(0);
    std::int32_t len = -1;
    fd_set rdFd;

    while(1) {
        FD_ZERO(&rdFd);
        FD_SET(handle, &rdFd);
        struct timeval to = {0, 100};
        auto ret = ::select(handle + 1, (fd_set *)&rdFd, (fd_set *)NULL, (fd_set *)NULL, &to); 
        len = -1;
        if(ret > 0 && FD_ISSET(handle, &rdFd)) {
            len = recv(handle, arr.data(), sizeof(std::int32_t), 0);
            if(!len) {
                std::cout << "line: " << __LINE__ << " closed" << std::endl;
                break;
            } else if(len > 0) {
                std::uint32_t payload_len; 
                std::istringstream istrstr;
                istrstr.rdbuf()->pubsetbuf(arr.data(), len);
                istrstr.read(reinterpret_cast<char *>(&payload_len), sizeof(payload_len));
                std::uint32_t offset = 0;
                payload_len = ntohl(payload_len);
                std::cout << "tcp payload length: " << payload_len << std::endl;

                std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
                while(1) {
                    len = recv(handle, (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
                    offset += len;
                    if(offset == payload_len) {
                        break;
                    }
                }
                if(offset == payload_len) {
                    std::string ss((char *)payload.get(), payload_len);
                    std::cout << "From TCP Client Received: " << ss << std::endl;
                    return(ss);
                }
            }
        } else if(!ret) {
            //timed out happens
            break;
        }
    }
    return(std::string());
}

noor::Uniimage::emp_t noor::Uniimage::rx(std::int32_t handle) {
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

        while(1) {
            len = recv(handle, (void *)(payload.get() + offset), (size_t)(payload_size - offset), 0);
            offset += len;
            if(offset == payload_size) {
                break;
            }
        }

        if(len > 0) {
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

std::string noor::Uniimage::build_web_response(Http& http) {
    //Build HTTP Response
    std::cout << "URI: " << http.uri() << " method: " << http.method() << std::endl;
    std::stringstream ss("");
    std::string payload("<html><title></title><head></head><body><h2>Redirecting to http://10.20.129.11</h2></body></html>");
    ss << "HTTP/1.1 301 Moved Permanently\r\n"
       << "Location: https://10.20.129.111\r\n"
       << "Content-length: " << payload.length() << "\r\n"
       << "Connection: close\r\n"
       << "Cookie: unity_token=IC3wWl66tT3XrqO88iLBSxCYbuxhPvGz; unity_login=admin; last_connection={\"success_last\":\"Sat Apr  8 03:47:22 2023\",\"success_from\":\"192.168.1.100\",\"failures\":0}" 
       << "\r\n\r\n"
       << payload;

    std::cout << "The Web Response is " << ss.str() << std::endl;
    return(ss.str());
}

std::int32_t noor::Uniimage::web_tx(std::int32_t channel, const std::string& data) {
    return(tcp_tx(channel, data));
}

std::string noor::Uniimage::web_rx(std::int32_t handle) {
    std::array<char, 1024> arr;
    arr.fill(0);
    std::int32_t len = -1;
    len = recv(handle, arr.data(), 1024, 0);
    if(!len) {
        std::cout << "line: " << __LINE__ << " closed" << std::endl;
    } else if(len > 0) {
        std::string ss(arr.data(), len);
        Http http(ss);
        std::cout << "URI: " << http.uri() << std::endl;
        std::cout << "Header " << http.header() << std::endl;
        std::cout << "Body " << http.body() << std::endl;
        std::uint32_t offset = 0;
        auto cl = http.value("Content-Length");
        size_t payload_len = 0;

        if(!cl.length()) {
            std::cout << "Content-Length is not present" << std::endl;
            auto response = build_web_response(http);
            if(!response.length()) {
                web_tx(handle, response);
                return(std::string("success"));
            }
        } else {
            std::cout << "value of Content-Length " << cl << std::endl;
            payload_len = std::stoi(cl);
            if(len == (payload_len + http.header().length())) {
                //We have received the full HTTP packet
                auto response = build_web_response(http);
                if(!response.length()) {
                    web_tx(handle, response);
                    return(std::string("success"));
                }
            } else {
                //compute the effective length
                payload_len = (std::stoi(cl) + http.header().length() - len);
                std::unique_ptr<char[]> payload = std::make_unique<char[]>(payload_len);
                std::int32_t tmp_len = 0;
                while(1) {
                    tmp_len = recv(handle, (void *)(payload.get() + offset), (size_t)(payload_len - offset), 0);
                    offset += tmp_len;
                    if(offset == payload_len) {
                        break;
                    }
                }
                if(offset == payload_len) {
                    std::string header(arr.data(), len);
                    std::string ss((char *)payload.get(), payload_len);
                    std::string request = header + ss;
                    std::cout << "From TCP Client Received: " << request << std::endl;
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

void noor::Uniimage::add_element(std::uint16_t type, std::uint16_t cmd, std::uint16_t message_id, const std::string& prefix, std::string response) {
    m_ds_request_list.push_back(std::make_tuple(type, cmd, message_id, prefix, response));
}

std::int32_t noor::Uniimage::create_and_connect_tcp_socket(const std::string& IP, std::uint16_t port) {
    //TCP Client .... 
    /* Set up the address we're going to bind to. */
    bzero(&m_tcp_server, sizeof(m_tcp_server));
    m_tcp_server.sin_family = AF_INET;
    m_tcp_server.sin_port = htons(port);
    m_tcp_server.sin_addr.s_addr = inet_addr(IP.c_str());
    memset(m_tcp_server.sin_zero, 0, sizeof(m_tcp_server.sin_zero));
    auto len = sizeof(m_tcp_server);

    std::int32_t channel = ::socket(PF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
    if(channel < 0) {
        std::cout << "Creation of INET socket Failed" << std::endl;
        return(-1);
    }
    tcp_client_fd(channel);
    tcp_client(Disconnected);

    /* set the reuse address flag so we don't get errors when restarting */
    auto flag = 1;
    if(::setsockopt(channel, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
        std::cout << "Error: Could not set reuse address option on INET socket!" << std::endl;
        close(tcp_client_fd());
        tcp_client_fd(-1);
        return(-1);
    }

    auto rc = ::connect(channel, (struct sockaddr *) &m_tcp_server, len);
    if(rc == -1) {
        if(errno == EINPROGRESS) {    
            //std::cout << "Connection is in-progress: "<< std::endl;
            tcp_client(Inprogress);
            return(0);
        } else {
            std::cout << "Connect is failed errno: "<< std::strerror(errno) << std::endl;
            close(tcp_client_fd());
            tcp_client_fd(-1);
            return(-1);
        }
    } else {
        tcp_client(Connected);
        return(0);
    }
}


std::int32_t noor::Uniimage::start_client() {
    //Read required Key's value from Data Store.
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
        FD_ZERO(&fdExcep);

        std::int32_t max_fd = uds_client_fd();

        FD_SET(uds_client_fd(), &fdList);
        if(tcp_client_fd() > 0 && tcp_client() == client_connection::Connected) {
            FD_SET(tcp_client_fd(), &fdList);
            max_fd = (max_fd > tcp_client_fd()) ? max_fd : tcp_client_fd();
        } else if(tcp_client_fd() > 0 && tcp_client() == client_connection::Inprogress) {
            FD_SET(tcp_client_fd(), &fdWrite);
            FD_SET(tcp_client_fd(), &fdExcep);
            max_fd = (max_fd > tcp_client_fd()) ? max_fd : tcp_client_fd();
        }

        conn_id = ::select((max_fd + 1), (fd_set *)&fdList, (fd_set *)&fdWrite, (fd_set *)NULL, (struct timeval *)&to);

        if(conn_id > 0) {
            if(FD_ISSET(uds_client_fd(), &fdList)) {

                //From Data store
                std::string request("");
                std::cout << "From DS line: " << __LINE__<<" Response received " << std::endl;
                auto req = rx(uds_client_fd());
                if(!req.m_response.length()) {
                    close(uds_client_fd());
                    uds_client(client_connection::Disconnected);
                    std::cout << "Data store is down" << std::endl;
                    exit(0);
                }
                if(tcp_client() == client_connection::Connected) {
                    //TCP Client is already connected, push the data
                    std::uint32_t payload_len = req.m_response.length();
                    payload_len = htonl(payload_len);
                    std::stringstream data("");
                    data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
                    data << req.m_response;
                    tcp_tx(tcp_client_fd(), data.str());

                } else {
                    //Cache the response and will be sent later when TCP connection is established
                    auto it = std::find_if(m_ds_request_list.begin(), m_ds_request_list.end(), [&](auto &inst) {
                    if(req.m_message_id == std::get<2>(inst)) {
                        //Update the recieved response
                        std::get<3>(inst) = req.m_response;
                        return(true);
                    }
                        return(false);
                    });
                }
            }
            else if(FD_ISSET(tcp_client_fd(), &fdWrite)) {
                //TCP connection established successfully.
                //Push changes if any now
                socklen_t optlen;
                std::int32_t optval = -1;
                optlen = sizeof (optval);
                if(getsockopt(tcp_client_fd(), SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0) {
                    //Failed
                    std::cout << "Async connect failed " << std::endl;
                } else if(optval == 1) {
                    //Connect is success.
                    FD_CLR(tcp_client_fd(), &fdWrite);
                    tcp_client(client_connection::Connected);
                    std::cout << "Connection with TCP server is established " << std::endl;
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
                } else {
                    //Connect is failed.
                    if(errno != EINPROGRESS)
                    std::cout << "line: " << __LINE__ << " connection status on fdWrite error:" << std::strerror(errno) << std::endl;
                    close(tcp_client_fd());
                    tcp_client(client_connection::Disconnected);
                    tcp_client_fd(-1);
                    create_and_connect_tcp_socket(m_config["server-ip"], std::stoi(m_config["server-port"]));
                }

            }
            else if(FD_ISSET(tcp_client_fd(), &fdExcep)) {
                //Connect Failed
                if(errno != EINPROGRESS) {
                    std::cout << "Exception on TCP Connect socket " << std::endl;
                    close(tcp_client_fd());
                    tcp_client(client_connection::Disconnected);
                    tcp_client_fd(-1);
                    create_and_connect_tcp_socket(m_config["server-ip"], std::stoi(m_config["server-port"]));
                }
            }
            else if(FD_ISSET(tcp_client_fd(), &fdList)) {
                //From TCP Server
                std::string request("");
                auto req = tcp_rx(tcp_client_fd());
                std::cout << "line: "<< __LINE__ << " Response received from TCP Server length:" << req.length() << std::endl;
                if(!req.length()) {
                    tcp_client(client_connection::Disconnected);
                    close(tcp_client_fd());
                    FD_CLR(tcp_client_fd(), &fdList);
                }
            }
        } 
        else if(!conn_id) {
            if(tcp_client_fd() > 0 && tcp_client() == client_connection::Disconnected) {
                auto ret = ::connect(tcp_client_fd(), (struct sockaddr *)&m_tcp_server, sizeof(m_tcp_server));
                if(ret > 0) {
                    std::cout << "line: " << __LINE__ << " Connected to TCP server: " << std::endl;
                    tcp_client(client_connection::Connected);
                    if(!m_ds_request_list.empty()) {
                        for(const auto& ent: m_ds_request_list) {
                            std::string payload = std::get<4>(ent);
                            std::uint32_t payload_len = payload.length();
                            payload_len = htonl(payload_len);
                            std::stringstream data("");
    
                            data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
                            data << payload;
                            tcp_tx(tcp_client_fd(), data.str());
                        }
                        m_ds_request_list.clear();
                    }
                } else if(ret == EINPROGRESS) {
                    //Connection is in progress
                    std::cout << "line: " << __LINE__ << " Connection to TCP server in progress " << std::endl;
                    tcp_client(client_connection::Inprogress);
                } else {
                    tcp_client(client_connection::Disconnected);
                }
            } else if(tcp_client_fd() < 0 && errno != EINPROGRESS) {
                std::cout << "line: " << __LINE__ << " Connection to TCP server initiated upon timedout " << std::endl;
                create_and_connect_tcp_socket(m_config["server-ip"], std::stoi(m_config["server-port"]));
            }
        }
    } /* End of while loop */
}

std::int32_t noor::Uniimage::start_server() {
    //Read required Key's value from Data Store.
    int conn_id   = -1;
    fd_set fdList;
    //newFd, IP, PORT,
    std::unordered_map<std::int32_t, std::tuple<std::int32_t, std::string, std::uint16_t>> conn;
    std::unordered_map<std::int32_t, std::tuple<std::int32_t, std::string, std::uint16_t>> web_conn;
    while (1) {
        /* A timeout for 100ms*/ 
        struct timeval to;
        to.tv_sec = 0;
        to.tv_usec = 100;
        FD_ZERO(&fdList);
        std::int32_t max_fd = tcp_server_fd();

        FD_SET(tcp_server_fd(), &fdList);

        if(web_server_fd() > 0) {
            max_fd = max_fd > web_server_fd() ? max_fd : web_server_fd();
            FD_SET(web_server_fd(), &fdList);
        }

        if(!conn.empty()){
            for(const auto& elm: conn) {
                max_fd = max_fd > elm.first ? max_fd : elm.first;
                FD_SET(elm.first, &fdList);
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
            if(FD_ISSET(tcp_server_fd(), &fdList)) {
                // accept a new connection 
                struct sockaddr_in peer;
                socklen_t peer_len = sizeof(peer);
                auto newFd = ::accept(tcp_server_fd(), (struct sockaddr *)&peer, &peer_len);
                if(newFd > 0) {
                    std::string IP(inet_ntoa(peer.sin_addr));
                    conn.insert(std::make_pair(newFd, std::make_tuple(newFd, IP, ntohs(peer.sin_port))));
                    auto ent = conn[newFd];
                    std::cout << "new connection line: " <<__LINE__ << " connId: " << std::get<0>(ent) << " IP: " << std::get<1>(ent) << " PORT: " << std::get<2>(ent) << std::endl;
                    FD_SET(newFd, &fdList);
                }
            } 
            else if(FD_ISSET(web_server_fd(), &fdList)) {
                // accept a new connection 
                struct sockaddr_in peer;
                socklen_t peer_len = sizeof(peer);
                auto newFd = ::accept(web_server_fd(), (struct sockaddr *)&peer, &peer_len);
                if(newFd > 0) {
                    std::string IP(inet_ntoa(peer.sin_addr));
                    web_conn.insert(std::make_pair(newFd, std::make_tuple(newFd, IP, ntohs(peer.sin_port))));
                    auto ent = web_conn[newFd];
                    std::cout << "new web connId: " << std::get<0>(ent) << " IP: " << std::get<1>(ent) << " PORT: " << std::get<2>(ent) << std::endl;
                    FD_SET(newFd, &fdList);
                }
            }
            else if(!conn.empty()) {
                for(const auto &elm: conn) {
                    auto channel = std::get<0>(elm);
                    if(FD_ISSET(channel, &fdList)) {
                        //From TCP Client
                        std::string request("");
                        std::cout << "Response received from TCP client: " << std::endl;
                        auto req = tcp_rx(channel);
                        if(!req.length()) {
                            //client is closed now
                            close(channel);
                            auto it = conn.erase(channel);
                        } else {
                            //std::cout << "Data TCP Server Received: " << req << std::endl;
                        }
                    }
                }
            }
            else if(!web_conn.empty()) {
                for(const auto &elm: web_conn) {
                auto channel = std::get<0>(elm);
                    if(FD_ISSET(channel, &fdList)) {
                        //From Web Client 
                        std::string request("");
                        std::cout << "Response from Web received on channel "<< channel << std::endl;
                        auto req = web_rx(channel);
                        if(!req.length()) {
                            //client is closed now 
                            close(channel);
                            auto it = conn.erase(channel);
                        }
                    }
                }
            }
        } /*conn_id > 0*/
    } /* End of while loop */
}

std::vector<struct option> options = {
    {"role",                      required_argument, 0, 'r'},
    {"server-ip",                 required_argument, 0, 'i'},
    {"server-port",               required_argument, 0, 'p'},
    {"web-port",                  required_argument, 0, 'w'},
    {"wan-interface-instance",    required_argument, 0, 'a'},
    {"protocol-tcp",              no_argument,       0, 't'},
    {"protocol-unix",             no_argument,       0, 'u'},
    {"protocol-udp",              no_argument,       0, 'd'},
};

int main(std::int32_t argc, char *argv[]) {
    std::int32_t c;
    std::int32_t option_index;
    std::string role("");
    std::unordered_map<std::string, std::string> config;

    while ((c = getopt_long(argc, argv, "r:i:p:w:tud:a:", options.data(), &option_index)) != -1) {
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
                config.insert(std::make_pair("protocol-tcp", std::to_string(1)));
            }
            break;
            case 'u':
            {
                config.insert(std::make_pair("protocol-unix", std::to_string(1)));
            }
            break;
            case 'd':
            {
                config.insert(std::make_pair("protocol-udp", std::to_string(1)));
            }
            break;
            default:
            {
                std::cout << "--role <client|server> " << std::endl
                          << "--server-ip <ip address of server> " << std::endl
                          << "--server-port <server port number> " << std::endl
                          << "--web-port <server-web-port for http request> " << std::endl
                          << "--protocol-tcp  <no Argument> " << std::endl
                          << "--protocol-udp  <no Argument> " << std::endl
                          << "--protocol-unix <no Argument> " << std::endl
                          << "--wan-interface-instance <c1|c3|c4|c5|w1|w2|e1|e2|e3> " << std::endl;
                          return(-1);
            }
        }
    }
    if(argc > 3) {
        noor::Uniimage unimanage(config);
        if(!role.compare("client")) {
            unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}}, {{"radio.mode__eq\": \"sta"}});
            //unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}});
            //unimanage.getVariable("net.interface.wifi[]");
            //unimanage.getVariable("services.sms.provision.enable");
            //unimanage.registerGetVariable("services.sms.provision.enable");
            unimanage.getVariable("device", {{"machine"}, {"product"}, {"provisioning.serial"}});
            unimanage.getVariable("net.interface.common[]", {{"ipv4.address"}, {"ipv4.connectivity"}, {"ipv4.prefixlength"}});
            unimanage.start_client();
        } else if(!role.compare("server")) {
            ///server 
            unimanage.start_server();
    }
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
