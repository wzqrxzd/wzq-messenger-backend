#include "register_route.hxx"
#include "error.hxx"
#include "types/UserFields.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

RegisterRoute::RegisterRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : Route(app, auth, db) {}

void RegisterRoute::setup()
{
  CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    return trySafe([&](){
      UserFields user = loadUserData(req);
      user.password = auth.hashPassword(user.password.value());

      ensureUserNotExist(user.username.value());
      insertUserToDB(user);

      auto token = auth.generateJWT(user.username.value());

      return buildRegisterRouteResponse(token); 
    });
  });
}

void RegisterRoute::ensureUserNotExist(const std::string& username)
{
  ConnectionGuard DB(dbHandle);
  pqxx::work worker(DB.get());

  pqxx::result result = worker.exec_prepared("find_user_by_username", username);

  if (!result.empty())
    throw AuthException(AuthError::UserAlreadyExist);
}

UserFields RegisterRoute::loadUserData(const crow::request& req)
{
  auto bodyJson = crow::json::load(req.body);

  UserFields user;

  user.name = getJsonField<std::string>(bodyJson, "name");
  user.username = getJsonField<std::string>(bodyJson, "username");
  user.password = getJsonField<std::string>(bodyJson, "password");
  user.description = "";

  return user;
}

// User.password must be hashed
void RegisterRoute::insertUserToDB(const UserFields& user)
{
  ConnectionGuard DB(dbHandle);
  pqxx::work worker(DB.get());

  worker.exec_prepared("insert_user", user.username, user.password, user.name, user.description);
  worker.commit();
}

inline crow::response RegisterRoute::buildRegisterRouteResponse(const std::string& token)
{
  return json_response(200, fmt::format(R"({{"status":"registered", "token":"{}"}})", token));
}
