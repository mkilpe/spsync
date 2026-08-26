file(GLOB SRC *.cpp *.hpp)
add_library(spsync_server_lib STATIC ${SRC})
target_link_libraries(spsync_server_lib spsync_protocol key_server server_common)

add_subdirectory(test)