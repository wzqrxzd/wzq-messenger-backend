#include "routes/user_update_info_route.hxx"
#include "error.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

UserUpdateInfoRoute::UserUpdateInfoRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void UserUpdateInfoRoute::setup()
{
  CROW_ROUTE(app, "/user/<int>").methods(crow::HTTPMethod::PATCH)([this](const crow::request& req, int userId){
    return trySafe([&](){
        if (!auth.authorizeRequest(req))
          throw AuthException(AuthError::TokenExpired);

        std::string token = req.get_header_value("Authorization").substr(7);
        std::string username = auth.getUsernameFromToken(token);

        auto body = crow::json::load(req.body);

        std::unordered_map<std::string, std::optional<std::string>> userInfoMap;

        userInfoMap["name"] = getOptionalJsonField<std::string>(body, "name");
        userInfoMap["username"] = getOptionalJsonField<std::string>(body, "username");
        userInfoMap["description"] = getOptionalJsonField<std::string>(body, "description");

        ConnectionGuard DB(dbHandle);
        pqxx::work W(DB.get());

        pqxx::result R = W.exec_prepared("get_username_by_id", userId);

        if (R[0]["username"].as<std::string>()!=username)
          throw AuthException(AuthError::PermissionDenied);

        W.exec_prepared("change_user_info",
            userId,
            userInfoMap["username"] ? userInfoMap["username"].value().c_str() : nullptr,
            userInfoMap["name"] ? userInfoMap["name"].value().c_str() : nullptr,
            userInfoMap["description"] ? userInfoMap["description"].value().c_str() : nullptr);
        
        W.commit();

        return json_response(200, R"({"status":"success"})");
    });
  });
}
