#include "routes/delete_message_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

DeleteMessageRoute::DeleteMessageRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void DeleteMessageRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>/messages/<int>").methods(crow::HTTPMethod::DELETE)([this](const crow::request& req, int chatId, int messageId){
    if (!auth.authorizeRequest(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = auth.getUsernameFromToken(token);

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());

      pqxx::result R_request_user = W.exec_prepared("find_user_by_username", username);
      pqxx::result R_user_message = W.exec_prepared("find_user_by_message", messageId);
      int userId = R_request_user[0]["id"].as<int>();
      int senderId = R_user_message[0]["sender_id"].as<int>();

      spdlog::info("userId = {}, senderId = {}", userId, senderId);

      if (userId != senderId)
        return json_response(401, R"({"error":"sender id != user id"})");

      W.exec_prepared("delete_message", messageId);

      W.commit();

      return json_response(200, fmt::format(R"({{"status":"deleted","message_id":"{}"}})",std::to_string(messageId)));
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return json_response(500, R"({"error":"Internal server error"})");
    }
  });

}
