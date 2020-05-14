
file(GLOB SRC *.cpp *.hpp)
add_application(spsync_storage_tool ${SRC})
add_deps(spsync_storage_tool spsync_core)
