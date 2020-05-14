add_subdirectory(server_lib)

file(GLOB SRC *.cpp *.hpp)
add_application(spsync_server ${SRC})
add_deps(spsync_server spsync_server_lib spsync_protocol server_common remote_object)
