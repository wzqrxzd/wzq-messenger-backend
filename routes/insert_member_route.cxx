#include "routes/insert_member_route.hxx"
#include "error.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

InsertMemberRoute::InsertMemberRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void InsertMemberRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>/add_user").methods(crow::HTTPMethod::POST)([this](const crow::request& req, int chatId){
    return trySafe([&](){
      if (!auth.authorizeRequest(req))
        throw AuthException(AuthError::TokenExpired);

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = auth.getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);

    std::string chatMember = getJsonField<std::string>(body_json, "username");

    ConnectionGuard DB(dbHandle);

    pqxx::work W(DB.get());
    pqxx::result R_insert_userId = W.exec_prepared("find_user_by_username", chatMember);
    pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
    int userId = R_request_userId[0]["id"].as<int>();
    int insertUserId = R_insert_userId[0]["id"].as<int>();

    pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

    if (R.empty())
      throw AuthException(AuthError::PermissionDenied);

    W.exec_prepared("insert_chat_member", chatId, insertUserId);

    pqxx::result R_chatname = W.exec_prepared("get_chatname_by_id", chatId);
    std::string chatName = R_chatname[0]["name"].as<std::string>();
    W.commit();

    wsController.notifyNewChat(chatId, insertUserId, chatName);

    return json_response(200, R"({"status":"user added"})");
  });
  });
}
