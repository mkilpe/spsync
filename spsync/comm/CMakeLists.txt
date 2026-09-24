file(GLOB SRC *.cpp *.hpp)
add_library(spsync_comm STATIC ${SRC})

set_target_properties(spsync_comm PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spsync_comm spsync_protocol network)
