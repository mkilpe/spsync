add_subdirectory(server_lib)

file(GLOB SRC *.cpp *.hpp)
add_application(spsync_server ${SRC})
add_deps(spsync_server spsync_server_lib spsync_engine spsync_core server_common asio_support remote_object crypto serialisation util log)
