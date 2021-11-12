file(GLOB SRC *.cpp *.hpp)
add_library(groupchat_json_protocol STATIC ${SRC})

set_target_properties(groupchat_json_protocol PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(groupchat_json_protocol groupchat_core)

add_subdirectory(test)