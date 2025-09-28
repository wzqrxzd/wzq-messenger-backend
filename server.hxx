#ifndef SERVER_HXX
#define SERVER_HXX

#include "crow.h"
#include <pqxx/pqxx>

class Server
{
  public:
    Server();
  private:
    void setup_routes();
    pqxx::connection connectDb();
    std::string hashPassword(const std::string& password);
    bool verifyPassword(const std::string& hash, const std::string& password);
    crow::SimpleApp app;
    const int port{8080};

    std::string secret;
    std::string dbname;
    std::string dbuser;
    std::string dbpass;
    std::string connectionString;
};

#endif
