cmake_minimum_required(VERSION 3.16.3)
project(uniimage)


#Adding Complier flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a -g -Wall -Wextra")

#include_directories(inc)

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "*.cc")

add_executable(uniimage ${SOURCES})
target_link_libraries(uniimage pthread ssl crypto)

install(TARGETS uniimage
	CONFIGURATIONS Release
        RUNTIME DESTINATION /usr/bin
)

