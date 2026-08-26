file(GLOB SRC *.cpp *.hpp)
add_library(spsync_client STATIC ${SRC})

set_target_properties(spsync_client PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spsync_client spsync_engine spsync_core packet_transport_client key_client)

add_subdirectory(test)
