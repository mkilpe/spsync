file(GLOB SRC *.cpp *.hpp)
add_library(spsync_engine STATIC ${SRC})

set_target_properties(spsync_engine PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spsync_engine spsync_core)

add_subdirectory(test)