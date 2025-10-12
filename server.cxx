#include "crow.h"
#include <spdlog/spdlog.h>
#include <libpq-fe.h>
#include "jwt-cpp/jwt.h"
#include <nlohmann/json.hpp>
#include <argon2.h>
#include "jwt_utils.hxx"
#include "env_utils.hxx"

#include "server.hxx"

Server::Server() {
  env_utils::loadEnvFile();
  secret = env_utils::getEnvVar("JWT_SECRET");
  dbname = env_utils::getEnvVar("POSTGRES_DB");
  dbuser = env_utils::getEnvVar("POSTGRES_USER");
  dbpass = env_utils::getEnvVar("POSTGRES_PASSWORD"); 

  connectionString =
  "dbname=" + dbname +
  " user=" + dbuser +
  " password=" + dbpass +
  " host=db";

  setupRoutes();
  app.port(port).multithreaded().run();
}


pqxx::connection Server::connectDB()
{
  try {
    auto x = pqxx::connection(connectionString.c_str());
    return x;
  } catch (const pqxx::broken_connection& e) {
    spdlog::error("{}", e.what());
    exit(1);
  }
}

std::string Server::hashPassword(const std::string& password)
{
  char hash[128];
  std::string salt = "random_salt_16";

  argon2i_hash_encoded(
  2,              // t_cost
        1 << 16,        // m_cost (64 MB)
        1,              // parallelism
        password.c_str(),
        password.size(),
        salt.c_str(),   // соль не nullptr
        salt.size(),
        32,             // hashlen (например 32 байта)
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

  if (!jwt_utils::verifyJWT(token, secret))
    return false;

  return true;
}

std::shared_ptr<pqxx::connection> Server::prepareDB()
{
  auto DB_ptr = std::make_shared<pqxx::connection>(connectDB());
  DB_ptr->prepare("insert_user", "INSERT INTO users(username, password_hash) VALUES($1, $2)");
  DB_ptr->prepare("find_user", "SELECT password_hash FROM users WHERE username=$1");


  DB_ptr->prepare("insert_chat", "INSERT INTO chats(name) VALUES($1) RETURNING id");
  DB_ptr->prepare("insert_chat_member", "INSERT INTO chat_members(chat_id, user_id) VALUES($1, $2)");
  DB_ptr->prepare("find_user_by_username", "SELECT id FROM users WHERE username=$1");
  DB_ptr->prepare(
    "insert_message",
    "INSERT INTO messages(chat_id, sender_id, content) VALUES($1, $2, $3) RETURNING id"
  );
  DB_ptr->prepare("delete_message",
    "DELETE FROM messages "
    "WHERE id = $1"
  );

  DB_ptr->prepare("delete_chat",
    "DELETE FROM chats WHERE id = $1"
  );

  DB_ptr->prepare("delete_chat_members",
    "DELETE FROM chat_members WHERE chat_id = $1"
  );

  DB_ptr->prepare("delete_chat_messages",
    "DELETE FROM messages WHERE chat_id = $1"
  );

  DB_ptr->prepare("check_user_in_chat",
    "SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id = $2"
  );

  DB_ptr->prepare("find_user_by_message",
    "SELECT sender_id FROM messages WHERE id=$1"
  );

  DB_ptr->prepare(
    "get_user_chats",
    "SELECT c.id, c.name FROM chats c "
    "JOIN chat_members cm ON c.id = cm.chat_id "
    "WHERE cm.user_id = $1"
  );

  DB_ptr->prepare(
    "get_chat_messages",
    "SELECT m.id, m.sender_id, m.content, m.read "
    "FROM messages m "
    "WHERE m.chat_id = $1 "
    "ORDER BY m.id ASC"
  );

  return DB_ptr;
}


void Server::setupRoutes()
{
  spdlog::info("setup_Routes start");

  auto DB = prepareDB();
  registerRoute(DB);
  loginRoute(DB);
  protectedRoute();
  createChatRoute(DB);
  sendMessageRoute(DB);
  deleteMessageRoute(DB);
  deleteChatRoute(DB);
  insertChatMemberRoute(DB);
  chatsRoute(DB);
  chatMessagesRoute(DB);
}
  
int main() {
  Server m;
}

