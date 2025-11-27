#include "route.hxx"
#include "delete_chat_route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

DeleteChatRoute::DeleteChatRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void DeleteChatRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>").methods(crow::HTTPMethod::DELETE)([this](const crow::request& req, int chatId){
    if (!auth.authorizeRequest(req))
      return json_response(401, "{\"error\":\"not valid token\"}");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = auth.getUsernameFromToken(token);

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());
      pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
      int userId = R_request_userId[0]["id"].as<int>();

      pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

      if (R.empty())
        return json_response(403, R"({"error":"user_not_in_the_chat"})");

      W.exec_prepared("delete_chat_messages", chatId);
      W.exec_prepared("delete_chat_members", chatId);
      W.exec_prepared("delete_chat", chatId);

      W.commit();

      wsController.notifyDeleteChat(chatId, userId);

      return json_response(200, R"({"status":"chat_deleted"})");
    } catch (const std::exception& e) {
        spdlog::info("DB error: {}", e.what());
        return json_response(500, R"({"error":"Internal server error"})");
    }
  });
}
