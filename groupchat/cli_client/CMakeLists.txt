
file(GLOB SRC *.cpp *.hpp)
add_application(gc-cli ${SRC})
add_deps(gc-cli groupchat_core)