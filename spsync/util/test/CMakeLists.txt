file(GLOB SRC *.cpp *.hpp)
add_test_application(test_spsync_util ${SRC})
add_deps(test_spsync_util spsync_util test_frame)