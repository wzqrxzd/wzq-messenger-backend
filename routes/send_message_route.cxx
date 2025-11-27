#include "routes/send_message_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

SendMessageRoute::SendMessageRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void SendMessageRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>/messages").methods(crow::HTTPMethod::POST)([this](const crow::request& req, int chatId){
    if (!auth.authorizeRequest(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = auth.getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("content"))
      return json_response(400, R"({"error":"invalid_json"})");

    std::string content = body_json["content"].s();


    ConnectionGuard DB(dbHandle);
    pqxx::work W(DB.get());
    pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
    int userId = R_user[0]["id"].as<int>();

    pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

    if (R.empty())
      return json_response(403, R"({"error":"user_not_in_the_chat"})");

    pqxx::result R_msg = W.exec_prepared("insert_message", chatId, userId, content);
    int messageId = R_msg[0]["id"].as<int>();

    W.commit();
    nlohmann::json notify_json = {
        {"type", "new_message"},
        {"chat_id", chatId},
        {"message_id", messageId},
        {"sender_id", userId},
        {"sender_name", username},
        {"content", content}
    };
    wsController.notifyNewMessage(chatId, notify_json.dump());
    spdlog::info("messageId = {}", messageId);
    return json_response(200, fmt::format(R"({{"status":"message_sent","message_id":"{}"}})", std::to_string(messageId)));
  });

}
