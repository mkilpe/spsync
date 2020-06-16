file(GLOB SRC *.cpp *.hpp)
add_library(spsync_util STATIC ${SRC})
target_link_libraries(spsync_util crypto common serialisation util log)

add_subdirectory(test)