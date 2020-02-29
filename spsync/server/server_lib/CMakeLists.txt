file(GLOB SRC *.cpp *.hpp)
add_library(spsync_server_lib STATIC ${SRC})
target_link_libraries(spsync_server_lib spsync_protocol)

add_subdirectory(test)