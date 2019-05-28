cmake_minimum_required(VERSION 3.10)

include("cmake.config" REQUIRED)

project("SPSync")

include("${sp_main_repository_path}/cmake.main")

# actual projects
add_subdirectory(spsync)
add_subdirectory(groupchat)
