#ifndef __uniimage__cc__
#define __uniimage__cc__

#include "ds_client.hpp"

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
	std::cout << "sent bytes: " << len << std::endl;
        if(len > 0) {
            offset += len;
            for(std::int32_t idx = 0; idx < 10; ++idx) {    
                printf("%X ", req.c_str()[idx]);
            }
            std::cout << "Request sent to TCP Server successfully" << std::endl;
        }
    } while(offset != len);

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
            for(std::int32_t idx = 0; idx < 10; ++idx) {    
                printf("%X ", req.c_str()[idx]);
            }
            std::cout << "Request sent to DS successfully" << std::endl;
        }
    } while(offset != len);

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
                //connection is closed
                close(handle);
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
	        if(len > 0) {
                    std::string ss((char *)payload.get(), payload_len);
	            std::cout << "From TCP Client Received: " << ss << std::endl;
	            //return(ss);
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

        std::cout << "type: " << type << " command: " << command << " message_id: " << message_id << " payload_size: " << payload_size << std::endl;
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
            try {
		std::cout << "Payload: " << ss << std::endl;
		emp_t res;
		res.m_type = type;
		res.m_command = command;
		res.m_message_id = message_id;
		res.m_response = ss;
                return(res);
            } catch (...) {
                std::cout << "Out of range for handle: " << handle << std::endl;
            }
        } else if(!len) {
            is_uds_client_connected(false);
            close(handle);
	}
    } else if(!len) {
        //connection is closed now.close(handle);
        is_uds_client_connected(false);
        //don't set to -1, we will try establishing connection soon.
        close(handle);

    }
    return(emp_t {});
}

std::string noor::Uniimage::web_rx(std::int32_t handle) {
    return(std::string());
}

void noor::Uniimage::add_element(std::uint16_t type, std::uint16_t cmd, std::uint16_t message_id, const std::string& prefix, std::string response) {
    m_ds_request_list.push_back(std::make_tuple(type, cmd, message_id, prefix, response));
}

std::int32_t noor::Uniimage::start_client() {
    //Read required Key's value from Data Store.
    int conn_id   = -1;
    fd_set fdList;
    fd_set fdwrite;

    while (1) {
        /* A timeout for 100ms*/ 
        struct timeval to;
        to.tv_sec = 0;
        to.tv_usec = 100;
        FD_ZERO(&fdList);
	FD_ZERO(&fdwrite);
        std::int32_t max_fd = uds_client_fd();

        FD_SET(uds_client_fd(), &fdList);

        if(tcp_client_fd() > 0 && !is_tcp_client_connected()) {
            //TCP Client connection is in progress
            FD_SET(tcp_client_fd(), &fdwrite);
            max_fd = (max_fd > tcp_client_fd()) ? max_fd : tcp_client_fd();
        } else if(tcp_client_fd() > 0 && is_tcp_client_connected()) {
            FD_SET(tcp_client_fd(), &fdList);
            max_fd = (max_fd > tcp_client_fd()) ? max_fd : tcp_client_fd();
	}

        conn_id = ::select((max_fd + 1), (fd_set *)&fdList, (fd_set *)&fdwrite, (fd_set *)NULL, (struct timeval *)&to);

        if(conn_id > 0) {
            if(FD_ISSET(uds_client_fd(), &fdList)) {

                //From Data store
                std::string request("");
                std::cout << "line: " << __LINE__<<" Response received " << std::endl;
                auto req = rx(uds_client_fd());

                if(is_tcp_client_connected()) {
		   //TCP Client is already connected, push the data
                    std::uint32_t payload_len = req.m_response.length();
                    payload_len = htonl(payload_len);
                    std::stringstream data("");
                    std::cout << "TCP: length: " << req.m_response.length() << std::endl; 
                    data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
		    data << req.m_response;
		    tcp_tx(tcp_client_fd(), data.str());
		    std::cout << "line: " << __LINE__<<" Response pushed to TCP Server data:  "<< data.str() << std::endl;
		} else {
		    auto it = std::find_if(m_ds_request_list.begin(), m_ds_request_list.end(), [&](auto &inst) {
		        if(req.m_message_id == std::get<2>(inst)) {
		            //std::get<4>(inst).assign(req.m_response);
                            return(true);			
		        }
		        return(false);
	            });

		    if(it != m_ds_request_list.end()) {
		        auto idx = std::distance(m_ds_request_list.begin(), it);
			std::get<4>(m_ds_request_list[idx]).assign(req.m_response);
		    }
		}
	    } 
	    else if(FD_ISSET(tcp_client_fd(), &fdwrite)) {
                //TCP connection established successfully.
		//Push changes if any now
		//auto ret = getsockopt(tcp_client_fd(), SOL_SOCKET, SO_ERROR, NULL, NULL);
		//if(!ret) {
		    m_is_tcp_server_down = false;
		    std::cout << "Connection with TCP server is established " << std::endl;
                    is_tcp_client_connected(true);
		//} else {
		  //  std::cout << "Connect failed to TCP server " << std::endl;
	//	}
#if 0
                for(const auto& ent: m_ds_request_list) {
		    std::string payload = std::get<4>(ent);
                    std::uint32_t payload_len = payload.length();
                    payload_len = htonl(payload_len);
                    std::stringstream data("");
    
                    data.write (reinterpret_cast <char *>(&payload_len), sizeof(payload_len));
		    data << payload;
		    tcp_tx(tcp_client_fd(), data.str());
		}
#endif
            } 
	    else if(FD_ISSET(tcp_client_fd(), &fdList)) {

                //From TCP Server
                std::string request("");
                auto req = tcp_rx(tcp_client_fd());
                std::cout << "line: "<< __LINE__ << " Response received from TCP Server length:" << req.length() << std::endl;
		if(!req.length()) {
		    is_tcp_client_connected(false);
		    close(tcp_client_fd());
		    m_is_tcp_server_down = true;
                }
            }
        } 
	else if(!conn_id) {
#if 0
            //timout happened --- try the connection if required.
            if(uds_client_fd() > 0) {

                if(!is_uds_client_connected()) {
                    auto ret = ::connect(uds_client_fd(), (struct sockaddr *)&m_uds_server, sizeof(m_uds_server));
                    if(ret > 0) {
                        is_uds_client_connected(true);
                    }
                }
            }
#endif
            if(tcp_client_fd() > 0) {
                if(m_is_tcp_server_down) {
                    auto ret = ::connect(tcp_client_fd(), (struct sockaddr *)&m_tcp_server, sizeof(m_tcp_server));
                    if(ret > 0) {
			std::cout << "line: " << __LINE__ << " Connected to TCP server: " << std::endl;
                        is_tcp_client_connected(true);
                    } else /*if(ret != EINPROGRESS)*/ {
			//Connection is in progress
			std::cout << "line: " << __LINE__ << " Connecting to TCP server: " << std::endl;
		        is_tcp_client_connected(false);
			m_is_tcp_server_down = false;
		    }
                } else {
		    //push data to TCP Server if any
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
	    if(FD_ISSET(web_server_fd(), &fdList)) {
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

	    if(!conn.empty()) {
                for(const auto &elm: conn) {
		    auto channel = std::get<0>(elm);
                    if(FD_ISSET(channel, &fdList)) {
                        //From TCP Server
                        std::string request("");
                        std::cout << "Response from TCP received " << std::endl;
                        auto req = tcp_rx(channel);
			if(!req.length()) {
			    //client is closed now 
                            auto it = conn.erase(channel);
			} else {
			    std::cout << "TCP Server Received: " << req << std::endl;
			}
		    }
                }
            }

	    if(!web_conn.empty()) {
                for(const auto &elm: web_conn) {
		    auto channel = std::get<0>(elm);
                    if(FD_ISSET(channel, &fdList)) {
                        //From TCP Server
                        std::string request("");
                        std::cout << "Response from Web received " << std::endl;
                        auto req = web_rx(channel);
			if(!req.length()) {
			    //client is closed now 
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
    std::string IP("");
    std::uint16_t port;
    std::uint16_t web_port;
    std::string wan_instance;
    using Value = std::variant<std::nullptr_t, std::string, std::uint32_t, bool, std::int32_t, std::uint16_t, std::int16_t, std::uint8_t, std::int8_t>;
    std::unordered_map<std::string, Value> config = {
        {"role",                   ""},
        {"server-ip",              ""},
        {"server-port",            0},
        {"web-port",               0},
        {"wan-interface-instance", ""},
        {"protocol-tcp",           false},
        {"protocol-udp",           false},
        {"protocol-unix",          false}
    };

    while ((c = getopt_long(argc, argv, "r:i:p:w:tuda:", options.data(), &option_index)) != -1) {
        switch(c) {
	    case 'r':
            {
                #if 0
                if(config["role"].compare("client") && (role.compare("server"))) {
                    std::cout << "Invalid value for --role, possible value is client or server "<< std::endl;
                    return(-1);
                }
                #endif
                config["role"] = optarg;
            }
	    break;
	    case 'i':
            {
                config["server-ip"] = optarg;
            }
	    break;
	    case 'p':
            {
                config["server-port"] = std::stoi(optarg);
            }
	    break;
	    case 'w':
            {
                config["web-port"] = std::stoi(optarg);
            }
	    break;
	    case 'a':
            {
                config["wan-interface-instance"] = optarg;
            }
        break;
        case 't':
            {
                config["protocol-tcp"] = true;
            }
        break;
        case 'u':
            {
                config["protocol-unix"] = true;
            }
        break;
        case 'd':
            {
                config["protocol-udp"] = true;
            }
	    break;
	    default:
	    {
              std::cout 
              << "--role                    <client|server> " << std::endl
			  << "--server-ip               <ip address of server> " << std::endl
			  << "--server-port             <server port number> " << std::endl
			  << "--web-port                <server-web-port for http request> " << std::endl
			  << "--wan-interface-instance  <c1|c3|c4|c5|w1|w2|e1|e2|e3> " << std::endl
              << "--protocol-tcp            <No Argument> " << std::endl
              << "--protocol-unix           <No Argument> " << std::endl
              << "--protocol-udp            <No Argument> " << std::endl;
	       return(-1);	
	    }
	}		
    }
    if(argc > 3) {
        for(auto& elm: config) {
            std::cout << "key: " << elm.first << " value: " ;
            std::visit([](auto arg){std::cout << arg << " ";}, elm.second);
        }
        noor::Uniimage unimanage(role, IP, port, web_port);
	if(!role.compare("client")) {
            unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}}, {{"radio.mode__eq\": \"sta"}});
            //unimanage.getVariable("net.interface.wifi[]", {{"radio.mode"}, {"mac"},{"ap.ssid"}});
            //unimanage.getVariable("net.interface.wifi[]");
            //unimanage.getVariable("services.sms.provision.enable");
            //unimanage.registerGetVariable("services.sms.provision.enable");
            //unimanage.getVariable("device", {{"machine"}, {"product"}, {"provisioning.serial"}});
            //unimanage.getVariable("net.interface.common[]", {{"ipv4.address"}, {"ipv4.connectivity"}, {"ipv4.prefixlength"}});
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
