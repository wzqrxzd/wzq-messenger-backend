#include "routes/send_message_route.hxx"
#include "error.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

SendMessageRoute::SendMessageRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void SendMessageRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>/messages").methods(crow::HTTPMethod::POST)([this](const crow::request& req, int chatId){
    return trySafe([&](){
      if (!auth.authorizeRequest(req))
        throw AuthException(AuthError::TokenExpired);

      auto body_json = crow::json::load(req.body); 

      std::string token = req.get_header_value("Authorization").substr(7);
      std::string username = auth.getUsernameFromToken(token);

      std::string content = getJsonField<std::string>(body_json, "content");

      ConnectionGuard DB(dbHandle);

      pqxx::work W(DB.get());
      pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
      int userId = R_user[0]["id"].as<int>();

      pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

      if (R.empty())
        throw AuthException(AuthError::PermissionDenied);

      pqxx::result R_msg = W.exec_prepared("insert_message", chatId, userId, content);
      int messageId = R_msg[0]["id"].as<int>();

      W.commit();

      wsController.notifyNewMessage(chatId, messageId, userId, username, content);

      return json_response(200, fmt::format(R"({{"status":"message_sent","message_id":"{}"}})", std::to_string(messageId)));
  });
  });

}
