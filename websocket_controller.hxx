#ifndef WEBSOCKET_CONTROLLER
#define WEBSOCKET_CONTROLLER

#include "auth_service.hxx"
#include "crow.h"
#include "database.hxx"
#include <functional>
#include <memory>
#include <nlohmann/json_fwd.hpp>
#include <set>

class WsRoute;

class WebsocketController {
  public:
    explicit WebsocketController();

    void notifyNewMessage(const int& chatId, const int& messageId, const int& senderId, const std::string& senderName, const std::string& content);
    void notifyNewChat(const int& chatId, const int& userId, const std::string& chatName);
    void notifyDeleteChat(const int& chatId, const int& userId);

    struct WsClient {
      crow::websocket::connection* conn;
      int userId;
      std::set<int> chatIds;
    };

  protected:
    std::mutex mtx;
    std::set<std::shared_ptr<WsClient>> wsClients;

    friend class WSRoute;
};

#endif
