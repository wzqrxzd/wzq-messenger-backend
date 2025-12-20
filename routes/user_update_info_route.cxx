#include "routes/user_update_info_route.hxx"
#include "error.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

UserUpdateInfoRoute::UserUpdateInfoRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void UserUpdateInfoRoute::setup()
{
  CROW_ROUTE(app, "/user/<int>").methods(crow::HTTPMethod::PATCH)([this](const crow::request& req, int expectedUserId){
    return trySafe([&](){
        const std::string username = auth.authorize(req);
        const UserFields updatedFields = parseRequest(req);

        ensureOwner(username, expectedUserId);
        changeUserData(updatedFields, expectedUserId);

        return crow::response(204);
    });
  });
}

UserFields UserUpdateInfoRoute::parseRequest(const crow::request& req)
{
  auto body = crow::json::load(req.body);
  UserFields updatedFields;

  updatedFields.name = getOptionalJsonField<std::string>(body, "name");
  updatedFields.username = getOptionalJsonField<std::string>(body, "username");
  updatedFields.description = getOptionalJsonField<std::string>(body, "description");

  return updatedFields;
}

void UserUpdateInfoRoute::ensureOwner(const std::string& username, const int& userId){
    ConnectionGuard DB(dbHandle);
    pqxx::work worker(DB.get());

    pqxx::result result = worker.exec_prepared("get_username_by_id", userId);
    const std::string expectedUsername = result[0]["username"].as<std::string>();

    if (expectedUsername!=username)
      throw AuthException(AuthError::PermissionDenied);

    worker.commit();
}


void UserUpdateInfoRoute::changeUserData(const UserFields& updatedFields, const int& userId)
{
  ConnectionGuard DB(dbHandle);
  pqxx::work worker(DB.get());

  worker.exec_prepared("change_user_info",
      userId,
      updatedFields.username ? updatedFields.username.value().c_str() : nullptr,
      updatedFields.username ? updatedFields.username.value().c_str() : nullptr,
      updatedFields.description ? updatedFields.description.value().c_str() : nullptr);

  worker.commit();
}
