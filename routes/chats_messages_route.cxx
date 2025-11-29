#include "routes/chats_messages_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

ChatsMessagesRoute::ChatsMessagesRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void ChatsMessagesRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>/messages").methods(crow::HTTPMethod::GET)([this](const crow::request& req, int chatId){
    return trySafe([&](){
      if (!auth.authorizeRequest(req))
        throw AuthException(AuthError::TokenExpired);
      std::string token = req.get_header_value("Authorization").substr(7);
      std::string username = auth.getUsernameFromToken(token);

      ConnectionGuard DB(dbHandle);

      pqxx::work W(DB.get());
      pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
      int userId = R_request_userId[0]["id"].as<int>();

      nlohmann::json res_json = nlohmann::json::array();

      pqxx::result check = W.exec_prepared("check_user_in_chat", chatId, userId);
      if (check.empty())
        return json_response(403, R"({"error":"user_not_in_chat"})"); 

      pqxx::result R = W.exec_prepared("get_chat_messages", chatId);
      for (auto row : R)
      {
        pqxx::result R = W.exec_prepared("get_username_by_id", userId);
        res_json.push_back({
          {"message_id", row["id"].as<int>()},
          {"sender_id", row["sender_id"].as<int>()},
          {"sender_name", row["sender_name"].as<std::string>()},
          {"content", row["content"].c_str()},
        });
      }

      return json_response(200, res_json);
    });
  });
}
