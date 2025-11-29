#include "routes/user_info_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

UserInfoRoute::UserInfoRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void UserInfoRoute::setup()
{
  CROW_ROUTE(app, "/user/<int>").methods(crow::HTTPMethod::GET)([this](const crow::request& req, int userId){
    return trySafe([&](){
      if (!auth.authorizeRequest(req))
        throw AuthException(AuthError::TokenExpired);

      std::string token = req.get_header_value("Authorization").substr(7);
      std::string username = auth.getUsernameFromToken(token);

      ConnectionGuard DB(dbHandle);
      pqxx::work W(DB.get());

      pqxx::result R = W.exec_prepared("get_user_by_id", userId);
      return json_response(200, fmt::format(R"({{"name":"{}","username":"{}","description":"{}","user_id":"{}"}})", R[0]["name"].as<std::string>(), R[0]["username"].as<std::string>(), R[0]["description"].as<std::string>(), userId));
  });
  });
}
