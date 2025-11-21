#ifndef SERVER_HXX
#define SERVER_HXX

#include "auth.hxx"
#include "crow.h"
#include "database.hxx"
#include "crow/middlewares/cors.h"
#include <pqxx/pqxx>
#include <functional>
#include <unordered_set>

class Server
{
  public:
    Server();
    void run();
  private:
    void setupRoutes();

    std::string hashPassword(const std::string& password);
    bool authorize(const crow::request& req);
    bool verifyPassword(const std::string& hash, const std::string& password);

    void registerRoute();
    void loginRoute();
    void protectedRoute();
    void createChatRoute();
    void sendMessageRoute();
    void deleteMessageRoute();
    void deleteChatRoute();
    void insertChatMemberRoute();
    void chatsRoute();
    void chatMessagesRoute();
    void webSocketMessageRoute();
    void userInfoRoute();

    crow::App<crow::CORSHandler> app;
    Database dbHandle;

    const int port{8080};

    const std::string secret;
};

#endif
