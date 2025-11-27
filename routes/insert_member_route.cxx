#include "routes/insert_member_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

InsertMemberRoute::InsertMemberRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void InsertMemberRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>/add_user").methods(crow::HTTPMethod::POST)([this](const crow::request& req, int chatId){
    if (!auth.authorizeRequest(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = auth.getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("username"))
      return json_response(400, R"({"error":"invalid_json"})");

    std::string chatMember = body_json["username"].s();

    ConnectionGuard DB(dbHandle);

    try {
      pqxx::work W(DB.get());
      pqxx::result R_insert_userId = W.exec_prepared("find_user_by_username", chatMember);
      pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
      int userId = R_request_userId[0]["id"].as<int>();
      int insertUserId = R_insert_userId[0]["id"].as<int>();

      pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

      if (R.empty())
        return json_response(403, R"({"error":"your_user_not_in_the_chat"})");

      W.exec_prepared("insert_chat_member", chatId, insertUserId);

      pqxx::result R_chatname = W.exec_prepared("get_chatname_by_id", chatId);
      std::string chatName = R_chatname[0]["name"].as<std::string>();
      W.commit();

      wsController.notifyNewChat(chatId, insertUserId, chatName);

      return json_response(200, R"({"status":"user added"})");
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return json_response(500, R"({"error":"Internal server error"})");
    }

  });
}
