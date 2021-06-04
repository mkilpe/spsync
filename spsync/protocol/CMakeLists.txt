file(GLOB SRC *.cpp *.hpp)
add_library(spsync_protocol STATIC ${SRC})
target_link_libraries(spsync_protocol spsync_core network)

add_subdirectory(test)