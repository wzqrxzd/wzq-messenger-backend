#ifndef SEND_MESSAGE_ROUTE
#define SEND_MESSAGE_ROUTE

#include "route.hxx"
#include "websocket_controller.hxx"
#include "crow.h"
#include "types/Message.hxx"

class SendMessageRoute : public WsAccessRoute
{
  public:
    explicit SendMessageRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
  private:
    std::string loadMessageContent(const crow::request& req);
    int getIdFromUsername(const std::string& username);
    void ensureUserInChat(const int& userId, const int& chatId);
    int insertMessageToDb(const Message& message);
    crow::response buildSendMessageResponse(const int& messageId);
};

#endif
