file(GLOB SRC *.cpp *.hpp records/*.cpp records/*.hpp)
add_library(spsync_core STATIC ${SRC})

set_target_properties(spsync_core PROPERTIES LINKER_LANGUAGE CXX)