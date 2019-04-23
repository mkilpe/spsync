file(GLOB SRC *.cpp *.hpp records/*.cpp records/*.hpp)
add_library(spsync_core STATIC ${SRC})

set_target_properties(spsync_core PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spsync_core spsync_util database)

add_subdirectory(test)