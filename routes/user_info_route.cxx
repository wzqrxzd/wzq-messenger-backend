#include "routes/user_info_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include "types/UserFields.hxx"

UserInfoRoute::UserInfoRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void UserInfoRoute::setup()
{
  CROW_ROUTE(app, "/user/<int>").methods(crow::HTTPMethod::GET)([this](const crow::request& req, int userId){
    return trySafe([&](){
      std::string username = auth.authorize(req);
      UserFields requestedUserInfo = getUserFieldsById(userId);

      return buildUserInfoResponse(requestedUserInfo);
    });
  });
}

UserFields UserInfoRoute::getUserFieldsById(const int& userId)
{
  ConnectionGuard DB(dbHandle);
  pqxx::work W(DB.get());

  pqxx::result R = W.exec_prepared("get_user_by_id", userId);
  return UserFields (
      R[0]["name"].as<std::string>(),
      R[0]["description"].as<std::string>(),
      R[0]["username"].as<std::string>()
  );
}

crow::response UserInfoRoute::buildUserInfoResponse(const UserFields& requestedUserInfo)
{
  return json_response(200,
      fmt::format(R"({{"name":"{}","username":"{}","description":"{}","user_id":"{}"}})",
        requestedUserInfo.username.value_or("").c_str(),
        requestedUserInfo.name.value_or("").c_str(),
        requestedUserInfo.description.value_or("").c_str(),
        requestedUserInfo.id.value_or(-1)
      )
  );
}
