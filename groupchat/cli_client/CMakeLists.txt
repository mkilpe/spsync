
file(GLOB SRC *.cpp *.hpp)
add_application(gc_cli ${SRC})
add_deps(gc_cli groupchat_core console event_system)