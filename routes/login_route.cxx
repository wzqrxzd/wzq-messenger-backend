#include "login_route.hxx"
#include "error.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

LoginRoute::LoginRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : Route(app, auth, db) {}

void LoginRoute::setup()
{
   CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    return trySafe([&](){
      auto body_json = crow::json::load(req.body);

      std::string username = getJsonField<std::string>(body_json, "username");
      std::string password = getJsonField<std::string>(body_json, "password");

      ConnectionGuard DB(dbHandle);

      pqxx::work W(DB.get());
      pqxx::result R = W.exec_prepared("find_user", username);

      if(R.size() == 0)
        throw AuthException(AuthError::InvalidCredentials, "wrong username");

      std::string storedHash = R[0]["password_hash"].c_str();

      if (!auth.verifyPassword(storedHash, password))
        throw AuthException(AuthError::InvalidCredentials, "wrong password");

      std::string token = auth.generateJWT(username);
      pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
      int user_id = R_user[0]["id"].as<int>();

      return json_response(200, fmt::format(R"({{"token":"{}","user_id":"{}"}})", token, user_id));
  });
  });
};
