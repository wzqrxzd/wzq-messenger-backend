#include "login_route.hxx"
#include "error.hxx"
#include "types/UserFields.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

LoginRoute::LoginRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : Route(app, auth, db) {}

void LoginRoute::setup()
{
   CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    return trySafe([&](){
      UserFields user = loadUserData(req);

      ensureUserExist(user.username.value());
      verifyPassword(user);

      std::string token = auth.generateJWT(user.username.value());
      int userId = getUserId(user.username.value());

      return buildLoginRouteResponse(token, userId); 
    });
  });
};


int LoginRoute::getUserId(const std::string& username)
{
  ConnectionGuard DB(dbHandle);

  pqxx::work worker(DB.get());

  pqxx::result result = worker.exec_prepared("find_user_by_username", username);
  int userId = result[0]["id"].as<int>();

  return userId;
}

UserFields LoginRoute::loadUserData(const crow::request& req)
{
  auto bodyJson = crow::json::load(req.body);

  UserFields user;
  user.username = getJsonField<std::string>(bodyJson, "username");
  user.password = getJsonField<std::string>(bodyJson, "password");

  return user;
}

void LoginRoute::ensureUserExist(const std::string& username)
{
  ConnectionGuard DB(dbHandle);

  pqxx::work W(DB.get());
  pqxx::result R = W.exec_prepared("find_user", username);

  if(R.size() == 0)
    throw AuthException(AuthError::InvalidCredentials, "wrong username");
}

void LoginRoute::verifyPassword(const UserFields& user)
{
  ConnectionGuard DB(dbHandle);

  pqxx::work worker(DB.get());
  pqxx::result result = worker.exec_prepared("find_user", user.username.value());

  std::string storedHash = result[0]["password_hash"].c_str();

  if (!auth.verifyPassword(storedHash, user.password.value()))
    throw AuthException(AuthError::InvalidCredentials, "wrong password");
}

inline crow::response LoginRoute::buildLoginRouteResponse(const std::string& token, const int& userId)
{
    return json_response(200,
        fmt::format(R"({{"token":"{}","user_id":"{}"}})",
          token,
          userId
    ));
}
