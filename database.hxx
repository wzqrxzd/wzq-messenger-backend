#ifndef DATABASE_HXX
#define DATABASE_HXX

#include <pqxx/pqxx>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstdint>

class DatabaseHandler
{
  public:
    using dbConnection = std::shared_ptr<pqxx::connection>;

    DatabaseHandler(const std::string& user, const std::string& name, const std::string& pass, uint16_t poolSize);
    ~DatabaseHandler();

    dbConnection aquireConnection();
    void releaseConnection(dbConnection conn);

  private:
    dbConnection prepareDB(dbConnection conn);

    std::queue<dbConnection> connPool;
    std::mutex mtx;
    std::condition_variable cv;

    const std::string connectionString;
};

class ConnectionGuard
{
  public:
    ConnectionGuard(DatabaseHandler& db) : db(db), conn(db.aquireConnection()) {};
    ~ConnectionGuard() { db.releaseConnection(conn); };
    pqxx::connection& get() { return *conn; }
    pqxx::connection* operator->() { return conn.get(); }
  private:
    DatabaseHandler& db;
    DatabaseHandler::dbConnection conn;
};


#endif
