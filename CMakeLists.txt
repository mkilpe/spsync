cmake_minimum_required(VERSION 3.10)

include("cmake.config" REQUIRED)

project("SPSync")

if(NOT sp_main_repository_path)
	message(FATAL_ERROR "sp_main_repository_path is required")
endif()

include("${sp_main_repository_path}/cmake.main")

if(ANDROID)
	message("-- Building for ${ANDROID_ABI}")
endif()

#find_package(Boost 1.75.0 REQUIRED)
get_filename_component(my_root_directory ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
#include_directories(${my_directory}/external/boost)
include_directories(${my_root_directory}/external/json/include)

add_definitions(-DBOOST_JSON_STANDALONE)

# actual projects
add_subdirectory(spsync)
add_subdirectory(groupchat)

# combined library for groupchat (used for mobile)
add_library(gc_lib STATIC
	$<TARGET_OBJECTS:groupchat_json_protocol>
	$<TARGET_OBJECTS:groupchat_core>

	$<TARGET_OBJECTS:spsync_client>
	$<TARGET_OBJECTS:spsync_comm>
	$<TARGET_OBJECTS:spsync_core>
	$<TARGET_OBJECTS:spsync_engine>
	$<TARGET_OBJECTS:spsync_protocol>
	$<TARGET_OBJECTS:spsync_util>

	$<TARGET_OBJECTS:packet_transport_client>
	$<TARGET_OBJECTS:packet_transport_protocol>
	$<TARGET_OBJECTS:key_client_lib>

	$<TARGET_OBJECTS:client_common>
	$<TARGET_OBJECTS:common>
	$<TARGET_OBJECTS:crypto>
	$<TARGET_OBJECTS:database>
	$<TARGET_OBJECTS:event_system>
	$<TARGET_OBJECTS:key_client_lib>
	$<TARGET_OBJECTS:log>
	$<TARGET_OBJECTS:network>
	$<TARGET_OBJECTS:remote_object>
	$<TARGET_OBJECTS:serialisation>
	$<TARGET_OBJECTS:util>
	)
