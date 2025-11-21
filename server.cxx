#include "crow.h"
#include <spdlog/spdlog.h>
#include <libpq-fe.h>
#include "jwt-cpp/jwt.h"
#include <nlohmann/json.hpp>
#include <argon2.h>
#include "jwt_utils.hxx"
#include "env_utils.hxx"
#include "server.hxx"
#include <sodium.h>

Server::Server() :
  dbHandle(
    env_utils::getEnvVar("POSTGRES_USER"),
    env_utils::getEnvVar("POSTGRES_DB"),
    env_utils::getEnvVar("POSTGRES_PASSWORD"),
    4
  ),
  secret(env_utils::getEnvVar("JWT_SECRET"))
{
  if (sodium_init() < 0) {
      throw std::runtime_error("libsodium init failed");
  }

  auto& cors = app.get_middleware<crow::CORSHandler>();
  cors.global()
    .origin("*")
    .methods(
        crow::HTTPMethod::Get,
        crow::HTTPMethod::Post,
        crow::HTTPMethod::Put,
        crow::HTTPMethod::Delete,
        crow::HTTPMethod::Options
    )
    .headers("Content-Type, Authorization")
    .allow_credentials();
  setupRoutes();
}

void Server::run() {
  app.port(port).multithreaded().run();
}

std::string Server::hashPassword(const std::string& password)
{
  char hash[128];
  uint8_t salt[16];
  randombytes_buf(salt, sizeof(salt));

  // memset(salt, 0x00, 16);
  //
  // auto saltGen = [](uint8_t* salt){
  //   std::random_device rd;
  //   for (int i{0}; i<16; i++)
  //   {
  //     *(salt+i) = static_cast<uint8_t>(rd() & 0xFF);
  //   }
  // };

  argon2i_hash_encoded(
  2,              // t_cost
        1 << 16,        // m_cost (64 MB)
        1,              // parallelism
        password.c_str(),
        password.size(),
        salt,
        sizeof(salt),
        32,             // hashlen
        hash,
        sizeof(hash)
  );
  return std::string(hash);
}

bool Server::verifyPassword(const std::string& hash, const std::string& password)
{
  return argon2i_verify(hash.c_str(), password.c_str(), password.size()) == ARGON2_OK;
}

bool Server::authorize(const crow::request& req)
{
  auto authHeader = req.get_header_value("Authorization");
  if (authHeader.empty())
    return false;

  std::string token = authHeader.substr(7);
  spdlog::info("{}", token);

  if (!jwt_utils::verifyJWT(token, secret))
    return false;

  return true;
}

void Server::setupRoutes()
{
  spdlog::info("setup_Routes start");

  registerRoute();
  loginRoute();
  protectedRoute();
  createChatRoute();
  sendMessageRoute();
  deleteMessageRoute();
  deleteChatRoute();
  insertChatMemberRoute();
  chatsRoute();
  chatMessagesRoute();
  webSocketMessageRoute();
  userInfoRoute();
}
  
int main() {
  Server m;
  m.run();
}

