cmake_minimum_required(VERSION 3.14)
project(wzq-message-server)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIBS ${CMAKE_SOURCE_DIR}/libs)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
add_compile_options(-Wdeprecated-declarations)

include(FetchContent)
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(json)

find_package(spdlog REQUIRED)
find_package(PostgreSQL REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(ARGON2_LIB argon2)
find_path(LIBSODIUM_INCLUDE_DIR sodium.h)
find_library(LIBSODIUM_LIBRARY sodium)
if(NOT LIBSODIUM_INCLUDE_DIR OR NOT LIBSODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found")
endif()

file(GLOB ROUTES_SRC "${CMAKE_SOURCE_DIR}/routes/*.cxx")

add_executable(wzq-message-server
  server.cxx
  env_utils.cxx
  database.cxx
  auth_service.cxx
  route_manager.cxx
  websocket_controller.cxx
  ${ROUTES_SRC}
)

target_include_directories(wzq-message-server PRIVATE ${CMAKE_SOURCE_DIR} ${LIBS}/crow/include/ ${LIBS}/jwt-cpp/include/ ${PostgreSQL_INCLUDE_DIRS} ${LIBSODIUM_INCLUDE_DIR})

target_link_libraries(wzq-message-server PRIVATE spdlog fmt pqxx ${ARGON2_LIB} nlohmann_json OpenSSL::SSL OpenSSL::Crypto ${PostgreSQL_LIBRARIES} ${LIBSODIUM_LIBRARY})
