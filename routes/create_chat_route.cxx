#include "create_chat_route.hxx"
#include "error.hxx"
#include "register_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

CreateChatRoute::CreateChatRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void CreateChatRoute::setup()
{
  CROW_ROUTE(app, "/chats").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    return trySafe([&](){
      if (!auth.authorizeRequest(req))
        throw AuthException(AuthError::TokenExpired);

      std::string token = req.get_header_value("Authorization").substr(7);
      std::string username = auth.getUsernameFromToken(token);

      auto body_json = crow::json::load(req.body);

      std::string chat_name = getJsonField<std::string>(body_json, "name");
      std::string usernameSecond = getJsonField<std::string>(body_json, "name");

      ConnectionGuard DB(dbHandle);

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
  });
  });

}
