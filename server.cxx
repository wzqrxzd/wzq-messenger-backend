#include "crow.h"
#include <spdlog/spdlog.h>
#include <libpq-fe.h>
#include "jwt-cpp/jwt.h"
#include <nlohmann/json.hpp>
#include <argon2.h>

#include "server.hxx"

void loadEnvFile(const std::string& filename = ".env") {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "⚠ Не удалось открыть файл " << filename << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t equalPos = line.find('=');
        if (equalPos == std::string::npos) continue;

        std::string key = line.substr(0, equalPos);
        std::string value = line.substr(equalPos + 1);

        if (!key.empty() && !value.empty()) {
            setenv(key.c_str(), value.c_str(), 1);
        }
    }
}

std::string getEnvVar(const char* key) {
    const char* value = std::getenv(key);
    if (!value) {
        throw std::runtime_error(std::string("Missing environment variable: ") + key);
    }
    return value;
}



Server::Server() {
  loadEnvFile();
  secret = getEnvVar("JWT_SECRET");
  dbname = getEnvVar("DB_NAME");
  dbuser = getEnvVar("DB_USER");
  dbpass = getEnvVar("DB_PASS"); 

  connectionString =
      "dbname=" + dbname +
      " user=" + dbuser +
      " password=" + dbpass;
  setup_routes();
  app.port(port).multithreaded().run();
}

pqxx::connection Server::connectDb()
{
  std::string connectionString = R"(dbname=wzq_messenger_db user=debian password="j=8wWKk.GnkT7&6[@%3rnEG1xlRTXk_KEhF|}D9WW,<^.PLB\)";
  try {
    auto x = pqxx::connection(connectionString.c_str());
    return x;
  } catch (const pqxx::broken_connection& e) {
    spdlog::error("{}", e.what());
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

bool Server::verifyJWT(const std::string& token)
{
  try {
    auto decoded = jwt::decode(token);
    jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256(this->secret))
        .with_issuer("wzq_server")
        .verify(decoded);
    return true;
  } catch (...) {
    return false;
  }
}

std::string Server::generateJWT(const std::string& username)
{
  auto token = jwt::create()
                .set_issuer("wzq_server")
                .set_type("JWT")
                .set_payload_claim("user", jwt::claim(username))
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes(60))
                .sign(jwt::algorithm::hs256{this->secret});
  return token;
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

      auto token = generateJWT(username);
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

      std::string token = generateJWT(username);
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

    if (!verifyJWT(token))
      return crow::response(400, "{\"error\":\"token expired\"}");     

    return crow::response("{\"status\":\"token_valid\"}");
  });
}

int main() {
  Server m;
}

