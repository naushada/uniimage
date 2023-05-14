cmake_minimum_required(VERSION 3.16.3)
project(uniimage)


#include_directories(/usr/local/include/bsoncxx/v_noabi)

#Adding Complier flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a -g -Wall -Wextra")

#include_directories(inc)
include_directories(/usr/local/ACE_TAO-7.0.0/include)

link_directories(/usr/local/ACE_TAO-7.0.0/lib)

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "*.cc")

add_executable(uniimage ${SOURCES})

#target_link_libraries(uniimage bsoncxx)
#target_link_libraries(uniimage pthread ssl crypto)
target_link_libraries(uniimage pthread ACE_SSL ACE)


install(TARGETS uniimage
	CONFIGURATIONS Release
        RUNTIME DESTINATION /usr/bin
)

