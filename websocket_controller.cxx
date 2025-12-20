#include "websocket_controller.hxx"
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

WebsocketController::WebsocketController() {}

void WebsocketController::notifyNewMessage(const Message& message)
{
  nlohmann::json notify = {
      {"type", "new_message"},
      {"chat_id", message.chatId},
      {"message_id", message.messageId},
      {"sender_id", message.senderId},
      {"sender_name", message.username},
      {"content", message.content}
  };

  std::lock_guard<std::mutex> lock(mtx);
  spdlog::info("cahtId {} message {}", message.chatId, message.content);
  for (auto& client : wsClients) {
    if (client->chatIds.count(message.chatId)) {
      client->conn->send_text(notify.dump());
    }
  }
}

void WebsocketController::notifyNewChat(const int& chatId, const int& userId, const std::string& chatName)
{
  nlohmann::json notify = {
    {"type", "new_chat"},
    {"chat_id", chatId},
    {"chat_name", chatName}
  };

  std::lock_guard<std::mutex> lock(mtx);
  for (auto& client : wsClients) {
    if (client->userId == userId) {
      client->chatIds.insert(chatId);
      client->conn->send_text(notify.dump());
      spdlog::info("[WS] Sent new_chat notify to userId={} chatId={}", userId, chatId);
    }
  }
}

void WebsocketController::notifyDeleteChat(const int& chatId, const int& userId)
{
  nlohmann::json notify = {
    {"type", "delete_chat"},
    {"chat_id", chatId}
  };

  {
    std::lock_guard<std::mutex> lock(mtx);
    for (auto& client : wsClients) {
      if (client->userId == userId) {
        client->chatIds.erase(chatId);
        client->conn->send_text(notify.dump());
        spdlog::info("[WS] Sent delete_chat notify to userId={} chatId={}", userId, chatId);
      }
    }
  }
}

