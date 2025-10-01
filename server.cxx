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
  dbname = env_utils::getEnvVar("DB_NAME");
  dbuser = env_utils::getEnvVar("DB_USER");
  dbpass = env_utils::getEnvVar("DB_PASS"); 

  connectionString =
  "dbname=" + dbname +
  " user=" + dbuser +
  " password=" + dbpass;
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

  CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req){
    auto body = req.body;

    auto body_json = crow::json::load(body);
    if (!body_json)
      return crow::response(400, "Invalid JSON");
    if (!body_json.has("username"))
      return crow::response(400, "Missing username field");
    if (!body_json.has("password"))
      return crow::response(400, "Missing password field");

    std::string username = body_json["username"].s();
    std::string password = body_json["password"].s();

    std::string hashedPassword = hashPassword(password);

    try {
      pqxx::work W(*DB);
      W.exec_prepared("insert_user", username, hashedPassword);
      W.commit();
      return crow::response("{\"status\":\"registered\"}");
    } catch (const std::exception& e)
    {
      spdlog::warn("error: {}", e.what());
      return crow::response("{\"error\":\"user already exists\"}");
    }

    auto token = jwt_utils::generateJWT(username, this->secret);
    spdlog::info("hash password: {}", hashPassword(password));

    return crow::response{std::string("{\"token\":\"") + token + "\"}"};
  });

  CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req){
    auto body = req.body;
    auto body_json = crow::json::load(body);
    if (!body_json)
      return crow::response(400, "Invalid JSON");
    if (!body_json.has("username"))
      return crow::response(400, "Missing username field");
    if (!body_json.has("password"))
      return crow::response(400, "Missing password field");

    std::string username = body_json["username"].s();
    std::string password = body_json["password"].s();

    try {
      pqxx::work W(*DB);
      pqxx::result R = W.exec_prepared("find_user", username);

      if(R.size() == 0)
        return crow::response{401, "{\"error\":\"unauthorized\"}"};

      std::string storedHash = R[0]["password_hash"].c_str();
      if (!verifyPassword(storedHash, password))
        return crow::response{401, "{\"error\":\"unauthorized\"}"};

      std::string token = jwt_utils::generateJWT(username, this->secret);
      return crow::response{std::string("{\"token\":\"") + token + "\"}"};
    } catch (const std::exception& e) {
      spdlog::error("error: {}", e.what());
      return crow::response(400, "{\"status\":\"bad_request\"}");
    }
  });

  CROW_ROUTE(app, "/protected").methods(crow::HTTPMethod::GET)([this](const crow::request& req){
    auto authHeader = req.get_header_value("Authorization");
    if (authHeader.empty())
      return crow::response(400, "{\"error\":\"missing_token\"}");     

    std::string token = authHeader.substr(7);

    if (!jwt_utils::verifyJWT(token, this->secret))
      return crow::response(400, "{\"error\":\"token expired\"}");     

    return crow::response("{\"status\":\"token_valid\"}");
  });

  CROW_ROUTE(app, "/create_chat").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req){
    if (!authorize(req))
      return crow::response(401, "{\"error\":\"not valid token\"}");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("name"))
      return crow::response(400, "{\"error\":\"invalid_json\"}");

    std::string chat_name = body_json["name"].s();

    try {
      pqxx::work W(*DB);

      int chat_id = W.exec_prepared("insert_chat", chat_name)[0]["id"].as<int>();
      pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
      int user_id = R_user[0]["id"].as<int>();

      W.exec_prepared("insert_chat_member", chat_id, user_id);
      W.commit();

      return crow::response("{\"chat_id\":" + std::to_string(chat_id) + "}");
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return crow::response(500, R"({"error":"Internal server error"})");
    }

  });

  CROW_ROUTE(app, "/send_message").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req){
    if (!authorize(req))
      return crow::response(401, "{\"error\":\"not valid token\"}");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("chat_id") || !body_json.has("content"))
      return crow::response(400, "{\"error\":\"invalid_json\"}");

    int chat_id = body_json["chat_id"].i();
    std::string content = body_json["content"].s();

    pqxx::work W(*DB);
    pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
    int user_id = R_user[0]["id"].as<int>();

    pqxx::result R_msg = W.exec_prepared("insert_message", chat_id, user_id, content);
    int message_id = R_msg[0]["id"].as<int>();

    W.commit();
    spdlog::info("messageId = {}", message_id);
    return crow::response("{\"status\":\"message_sent\",\"message_id\":" + std::to_string(message_id) + "}");
  });

  CROW_ROUTE(app, "/delete_message").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req){
    if (!authorize(req))
      return crow::response(401, "{\"error\":\"not valid token\"}");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("message_id"))
      return crow::response(400, "{\"error\":\"invalid_json\"}");

    int message_id = body_json["message_id"].i();

    try {
      pqxx::work W(*DB);
      pqxx::result R_request_user = W.exec_prepared("find_user_by_username", username);
      pqxx::result R_user_message = W.exec_prepared("find_user_by_message", message_id);
      int userId = R_request_user[0]["id"].as<int>();
      int senderId = R_user_message[0]["sender_id"].as<int>();

      spdlog::info("userId = {}, senderId = {}", userId, senderId);

      if (userId != senderId)
        return crow::response(401, "{\"error\":\"sender id != user id\"}");

      W.exec_prepared("delete_message", message_id);

      W.commit();
      return crow::response("{\"status\":\"deleted\",\"message_id\":" + std::to_string(message_id) + "}");
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return crow::response(500, R"({"error":"Internal server error"})");
    }
  });

  CROW_ROUTE(app, "/chat/<int>/delete").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req, int chatId){
    if (!authorize(req))
      return crow::response(401, "{\"error\":\"not valid token\"}");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    try {
      pqxx::work W(*DB);
      pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
      int userId = R_request_userId[0]["id"].as<int>();

      pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

      if (R.empty())
        return crow::response(403, "{\"error\":\"user_not_in_the_chat\"}");

      W.exec_prepared("delete_chat_messages", chatId);
      W.exec_prepared("delete_chat_members", chatId);
      W.exec_prepared("delete_chat", chatId);

      W.commit();

      return crow::response(200, "{\"status\":\"chat_deleted\"}");
    } catch (const std::exception& e) {
        spdlog::info("DB error: {}", e.what());
        return crow::response(500, R"({"error":"Internal server error"})");
    }
  });

  CROW_ROUTE(app, "/insert_chat_member").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req){
    if (!authorize(req))
      return crow::response(401, "{\"error\":\"not valid token\"}");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("chat_id") || !body_json.has("user_id"))
      return crow::response(400, "{\"error\":\"invalid_json\"}");

    int chatId = body_json["chat_id"].i();
    int insertUserId = body_json["user_id"].i();

    try {
      pqxx::work W(*DB);
      pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
      int userId = R_request_userId[0]["id"].as<int>();

      pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

      if (R.empty())
        return crow::response(403, "{\"error\":\"your_user_not_in_the_chat\"}");

      W.exec_prepared("insert_chat_member", chatId, insertUserId);
      W.commit();

      return crow::response(200, "{\"status\":\"user added\"}");
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return crow::response(500, R"({"error":"Internal server error"})");
    }

  });

  CROW_ROUTE(app, "/chats").methods(crow::HTTPMethod::GET)([this, DB](const crow::request& req){
    if (!authorize(req))
      return crow::response(401, "{\"error\":\"not valid token\"}");
    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    pqxx::work W(*DB);
    pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
    int userId = R_request_userId[0]["id"].as<int>();

    nlohmann::json res_json = nlohmann::json::array();

    try {
      pqxx::result R = W.exec_prepared("get_user_chats", userId);

      for (auto row : R)
      {
        res_json.push_back({
          {"chat_id", row["id"].as<int>()},
          {"chat_name", row["name"].c_str()}
        });
      }
    } catch (...) {
      spdlog::error("get_user_chats error");
      return crow::response(500, "{\"error\":\"server_error\"}");
    }

    return crow::response(res_json.dump());
  });

  CROW_ROUTE(app, "/chat/<int>/messages").methods(crow::HTTPMethod::GET)([this, DB](const crow::request& req, int chatId){
    if (!authorize(req))
      return crow::response(401, "{\"error\":\"not valid token\"}");
    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    pqxx::work W(*DB);
    pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
    int userId = R_request_userId[0]["id"].as<int>();

    nlohmann::json res_json = nlohmann::json::array();

    try {
      pqxx::result check = W.exec_prepared("check_user_in_chat", chatId, userId);
      if (check.empty())
        return crow::response(403, "{\"error\":\"user_not_in_chat\"}"); 

      pqxx::result R = W.exec_prepared("get_chat_messages", chatId);
      for (auto row : R)
      {
        res_json.push_back({
          {"message_id", row["id"].as<int>()},
          {"sender_id", row["sender_id"].as<int>()},
          {"content", row["content"].c_str()},
          {"read", row["read"].as<bool>()}
        });
      }

      return crow::response(res_json.dump());
    } catch (...) {
      spdlog::error("get_chat_messages error");
      return crow::response(500, "{\"error\":\"server_error\"}");
    }
  });
}

int main() {
Server m;
}

