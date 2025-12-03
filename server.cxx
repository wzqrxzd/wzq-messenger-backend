#include "crow.h"
#include <spdlog/spdlog.h>
#include <libpq-fe.h>
#include <argon2.h>
#include "crow/common.h"
#include "env_utils.hxx"
#include "server.hxx"
#include <sodium.h>
#include "routes/chats_messages_route.hxx"
#include "routes/create_chat_route.hxx"
#include "routes/delete_message_route.hxx"
#include "routes/insert_member_route.hxx"
#include "routes/register_route.hxx"
#include "routes/login_route.hxx"
#include "routes/send_message_route.hxx"
#include "routes/chats_route.hxx"
#include "routes/user_info_route.hxx"
#include "routes/user_update_info_route.hxx"
#include "routes/ws_route.hxx"
#include "websocket_controller.hxx"

Server::Server() :
  dbHandle(
    env_utils::getEnvVar("POSTGRES_USER"),
    env_utils::getEnvVar("POSTGRES_DB"),
    env_utils::getEnvVar("POSTGRES_PASSWORD"),
    4
  ),
  secret(env_utils::getEnvVar("JWT_SECRET")),
  auth(),
  routeManager(app, auth, dbHandle)
{
  if (sodium_init() < 0) {
      throw std::runtime_error("libsodium init failed");
  }

  auto& cors = app.get_middleware<crow::CORSHandler>();
  cors.global()
    .origin("*")
    .methods(
        crow::HTTPMethod::Get,
        crow::HTTPMethod::Patch,
        crow::HTTPMethod::Post,
        crow::HTTPMethod::Put,
        crow::HTTPMethod::Delete,
        crow::HTTPMethod::Options
    )
    .headers("Content-Type, Authorization")
    .allow_credentials();

  spdlog::set_level(spdlog::level::debug);
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");

  setupRoutes();
}

void Server::run() {
  app.port(port).multithreaded().run();
}

void Server::setupRoutes()
{
  spdlog::info("setup routes start");

  routeManager.addRoute<WSRoute>();
  routeManager.addRoute<LoginRoute>();
  routeManager.addRoute<RegisterRoute>();
  routeManager.addRoute<SendMessageRoute>();
  routeManager.addRoute<ChatsRoute>();
  routeManager.addRoute<ChatsMessagesRoute>();
  routeManager.addRoute<CreateChatRoute>();
  routeManager.addRoute<InsertMemberRoute>();
  routeManager.addRoute<DeleteMessageRoute>();
  routeManager.addRoute<UserInfoRoute>();
  routeManager.addRoute<UserUpdateInfoRoute>();

  routeManager.setupRoutes();
}
  
int main() {
  Server m;
  m.run();
}

