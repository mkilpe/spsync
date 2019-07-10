file(GLOB SRC *.cpp *.hpp)
add_library(spsync_test STATIC ${SRC})

set_target_properties(spsync_test PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spsync_test spsync_engine)
