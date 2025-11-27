#include "create_chat_route.hxx"
#include "register_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

CreateChatRoute::CreateChatRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void CreateChatRoute::setup()
{
  CROW_ROUTE(app, "/chats").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    if (!auth.authorizeRequest(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = auth.getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("name"))
      return json_response(400, R"({"error":"invalid_json"})");
    if (!body_json || !body_json.has("username"))
      return json_response(400, R"({"error":"invalid_json"})");

    std::string chat_name = body_json["name"].s();
    std::string usernameSecond = body_json["username"].s();

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());

      int chat_id = W.exec_prepared("insert_chat", chat_name)[0]["id"].as<int>();

      pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
      int user_id = R_user[0]["id"].as<int>();

      W.exec_prepared("insert_chat_member", chat_id, user_id);

      pqxx::result R_userSecond = W.exec_prepared("find_user_by_username", usernameSecond);
      int userSecond_id = R_userSecond[0]["id"].as<int>();

      W.exec_prepared("insert_chat_member", chat_id, userSecond_id);

      W.commit();

      wsController.notifyNewChat(chat_id, user_id, chat_name);
      wsController.notifyNewChat(chat_id, userSecond_id, chat_name);

      return json_response(200, fmt::format(R"({{"chat_id":"{}"}})", std::to_string(chat_id)));
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return json_response(500, R"({"error":"Internal server error"})");
    }
  });

}
