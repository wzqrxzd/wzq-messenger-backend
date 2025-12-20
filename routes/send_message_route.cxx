#include "routes/send_message_route.hxx"
#include "error.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include "types/Message.hxx"

SendMessageRoute::SendMessageRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void SendMessageRoute::setup()
{
  CROW_ROUTE(app, "/chats/<int>/messages").methods(crow::HTTPMethod::POST)([this](const crow::request& req, int chatId){
    return trySafe([&](){
      const std::string username = auth.authorize(req);
      const int userId = getIdFromUsername(username);

      ensureUserInChat(userId, chatId);

      const std::string content = loadMessageContent(req);

      Message message;
      message.username = username;
      message.senderId = userId;
      message.chatId = chatId;
      message.content = content;
      message.messageId = insertMessageToDb(message);

      wsController.notifyNewMessage(message);

      return buildSendMessageResponse(message.messageId); 
  });
  });
}

std::string SendMessageRoute::loadMessageContent(const crow::request& req)
{
  auto bodyJson = crow::json::load(req.body);
  std::string content = getJsonField<std::string>(bodyJson, "content");
  
  return content;
}

int SendMessageRoute::getIdFromUsername(const std::string& username)
{
    ConnectionGuard DB(dbHandle);

    pqxx::work worker(DB.get());
    pqxx::result result = worker.exec_prepared("find_user_by_username", username);
    int userId = result[0]["id"].as<int>();

    return userId;
}

void SendMessageRoute::ensureUserInChat(const int& userId, const int& chatId)
{
  ConnectionGuard DB(dbHandle);

  pqxx::work worker(DB.get());
  pqxx::result result = worker.exec_prepared("check_user_in_chat", chatId, userId);

  if (result.empty())
    throw AuthException(AuthError::PermissionDenied);
}

int SendMessageRoute::insertMessageToDb(const Message& message)
{
  ConnectionGuard DB(dbHandle);
  pqxx::work worker(DB.get());

  pqxx::result result = worker.exec_prepared("insert_message",
    message.chatId,
    message.senderId,
    message.content
  );
  int messageId = result[0]["id"].as<int>();

  worker.commit();
  return messageId;
}

crow::response SendMessageRoute::buildSendMessageResponse(const int& messageId)
{
  return json_response(200,
    fmt::format(R"({{"status":"message_sent","message_id":"{}"}})",
      std::to_string(messageId)
    )
  );
}
