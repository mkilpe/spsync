file(GLOB SRC *.cpp *.hpp)
add_library(spsync_transfer STATIC ${SRC})

set_target_properties(spsync_transfer PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spsync_transfer spsync_protocol network)

add_subdirectory(test)
