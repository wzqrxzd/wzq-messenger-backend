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
  setup_routes();
  app.port(port).multithreaded().run();
}

pqxx::connection Server::connectDb()
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
  std::string salt = "random_salt_16"; // или сгенерировать случайно

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

void Server::setup_routes()
{
  spdlog::info("setup_routes start");

  auto DB = std::make_shared<pqxx::connection>(connectDb());
  DB->prepare("insert_user", "INSERT INTO users(username, password_hash) VALUES($1, $2)");
  DB->prepare("find_user", "SELECT password_hash FROM users WHERE username=$1");

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
        spdlog::info("{}", e.what());
        return crow::response("{\"status\":\"user already exists\"}");
      }

      auto token = jwt_utils::generateJWT(username, this->secret);
      spdlog::info("hash password: {}", hashPassword(password));

      return crow::response{std::string("{\"token\":\"") + token + "\"}"};
  });

  CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([this, DB](const crow::request& req){
      try {
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

      pqxx::work W(*DB);
      pqxx::result R = W.exec_prepared("find_user", username);

      if(R.size() == 0)
        return crow::response{401, "{\"error\":\"unauthorized\"}"};

      std::string storedHash = R[0]["password_hash"].c_str();
      if (!verifyPassword(storedHash, password))
        return crow::response{401, "{\"error\":\"unauthorized\"}"};

      std::string token = jwt_utils::generateJWT(username, this->secret);
      return crow::response{std::string("{\"token\":\"") + token + "\"}"};
    } catch (...) {
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
}

int main() {
  Server m;
}

