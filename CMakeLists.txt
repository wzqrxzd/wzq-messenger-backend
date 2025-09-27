cmake_minimum_required(VERSION 3.14)
project(wzq-message-server)

set(CMAKE_CXX_STANDART 23)
set(CMAKE_CXX_STANDART_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

find_package(spdlog REQUIRED)

add_executable(wzq-message-server
  server.cxx
)

target_include_directories(wzq-message-server PRIVATE ${CMAKE_SOURCE_DIR}/crow/include/)

target_link_libraries(wzq-message-server PRIVATE spdlog fmt)
