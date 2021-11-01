file(GLOB SRC *.cpp *.hpp)
add_library(groupchat_core STATIC ${SRC})

set_target_properties(groupchat_core PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(groupchat_core spsync_client spsync_engine)

add_subdirectory(test)