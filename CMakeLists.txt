cmake_minimum_required(VERSION 3.10)

include("cmake.config" REQUIRED)

project("SPSync")

if(NOT sp_main_repository_path)
	message(FATAL_ERROR "sp_main_repository_path is required")
endif()

include("${sp_main_repository_path}/cmake.main")

#find_package(Boost 1.75.0 REQUIRED)
#get_filename_component(my_directory ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
#include_directories(${my_directory}/external/boost)

#add_definitions(-DBOOST_JSON_STANDALONE)

# actual projects
add_subdirectory(spsync)
add_subdirectory(groupchat)
