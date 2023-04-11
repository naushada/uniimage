#ifndef __http_cc__
#define __http_cc__

#include "http.hpp"

// HTTP =====================

/**
 * @brief 
 * 
 * @param param 
 */
void noor::Http::format_value(const std::string& param) {
  auto offset = param.find_first_of("=", 0);
  auto name = param.substr(0, offset);
  auto value = param.substr((offset + 1));
  std::stringstream input(value);
  std::int32_t c;
  value.clear();

  while((c = input.get()) != EOF) {
    switch(c) {
      case '+':
        value.push_back(' ');
      break;

      case '%':
      {
        std::int8_t octalCode[3];
        octalCode[0] = (std::int8_t)input.get();
        octalCode[1] = (std::int8_t)input.get();
        octalCode[2] = 0;
        std::string octStr((const char *)octalCode, 3);
        std::int32_t ch = std::stoi(octStr, nullptr, 16);
        value.push_back(ch);
      }
      break;

      default:
        value.push_back(c);
    }
  }

  if(!value.empty() && !name.empty()) {
    add_element(name, value);
  }
}

/**
 * @brief 
 * 
 * @param in 
 */
void noor::Http::parse_uri(const std::string& in)
{
  std::string delim("\r\n");
  size_t offset = in.find_first_of(delim, 0);

  if(std::string::npos != offset) {
    /* Qstring */
    std::string first_line = in.substr(0, offset);
    std::cout << "line: " << __LINE__ <<"The request string is " << first_line << std::endl;

    offset = first_line.find_first_of(" ", 0);
    // HTTP Request line must start with method - GET/POST/PUT/DELETE/OPTIONS
    if(std::string::npos != offset) {

      //e.g. The request string is GET /webui/main.04e34705edfe295e.js HTTP/1.1
      auto req_method = first_line.substr(0, offset);
      method(req_method); //GET/POST/PUT/DELETE/OPTIONS
      offset = first_line.find_first_of("?");

      if(std::string::npos == offset) {

        //'?' is not present in the first_line, which means QS - Query String is not present
        //e.g. The request string is GET /webui/main.04e34705edfe295e.js HTTP/1.1
        offset = first_line.find_first_of(" ", method().length() + 1);

        if(std::string::npos != offset) {
          auto resource_uri = first_line.substr(0, offset);
          uri(resource_uri);
          return;
        }

      } else {

        auto resource_uri = first_line.substr(method().length() + 1, offset - (method().length() - 1));
        uri(resource_uri);
      }
    }

    std::string QS(first_line.substr(offset + 1));
    offset = QS.find_last_of(" ");
    QS = QS.substr(0, offset);

    while(true) {

      offset = QS.find_first_of("&");
      if(std::string::npos == offset) {
        format_value(QS);
        break;
      }
      auto key_value = QS.substr(0, offset);
      format_value(key_value);
      QS = QS.substr(offset+1);

    }
  }
}

/**
 * @brief 
 * 
 * @param in 
 */
void noor::Http::parse_header(const std::string& in)
{
  std::stringstream input(in);
  std::string line_str;
  line_str.clear();

  /* getridof first request line 
   * GET/POST/PUT/DELETE <uri>?uriName[&param=value]* HTTP/1.1\r\n
   */
  std::getline(input, line_str, '\r');

  auto offset = input.str().find_last_of("\r\n\r\n");
  if(std::string::npos != offset) {
    //HTTP Header part
    auto header = input.str().substr(0, offset);
    std::stringstream ss(header);

    while(!ss.eof()) {

      line_str.clear();
      std::getline(ss, line_str, '\r');
      offset = line_str.find_first_of(": ", 0);
      auto key = line_str.substr(0, offset);
      auto value = line_str.substr(offset+2);
      //getting rid oftrailing \r\n
      offset = value.find_first_of("\r\n");
      value = value.substr(0, offset);

      if(!key.empty() && !value.empty()) {
        add_element(key, value);
      }
    }
  }
}

std::string noor::Http::get_header(const std::string& in)
{
  std::string header("");
  auto offset = in.find_last_of("\r\n\r\n");
  if(std::string::npos != offset) {
    header = in.substr(0, offset);
  }
  std::cout << "line: " << __LINE__ << " HTTP Header " << header << std::endl;
  return(header);

}

std::string noor::Http::get_body(const std::string& in)
{
  auto header = get_header(in);
  auto bdy = in.substr(header.length(), in.length() - header.length());
  return(bdy);
}

#endif /*__http_cc__*/
