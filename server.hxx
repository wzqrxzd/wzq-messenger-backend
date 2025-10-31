#ifndef SERVER_HXX
#define SERVER_HXX

#include "crow.h"
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

    using dbConnection = std::shared_ptr<pqxx::connection>;

    std::string hashPassword(const std::string& password);
    bool authorize(const crow::request& req);
    bool verifyPassword(const std::string& hash, const std::string& password);

    void registerRoute(dbConnection DB);
    void loginRoute(dbConnection DB);
    void protectedRoute();
    void createChatRoute(dbConnection DB);
    void sendMessageRoute(dbConnection DB);
    void deleteMessageRoute(dbConnection DB);
    void deleteChatRoute(dbConnection DB);
    void insertChatMemberRoute(dbConnection DB);
    void chatsRoute(dbConnection DB);
    void chatMessagesRoute(dbConnection DB);
    void webSocketMessageRoute(dbConnection DB);

    dbConnection connectDB();
    dbConnection prepareDB();

    crow::App<crow::CORSHandler> app;

    const int port{8080};

    std::string secret;
    std::string dbname;
    std::string dbuser;
    std::string dbpass;
    std::string connectionString;
};

#endif
