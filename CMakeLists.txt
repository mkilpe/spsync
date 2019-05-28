cmake_minimum_required(VERSION 3.10)

include("cmake.config" REQUIRED)

project("SPSync")

if(NOT sp_main_repository_path)
	message(FATAL_ERROR "sp_main_repository_path is required")
endif()

include("${sp_main_repository_path}/cmake.main")

# actual projects
add_subdirectory(spsync)
add_subdirectory(groupchat)
