#ifndef DATABASE_HXX
#define DATABASE_HXX

#include <pqxx/pqxx>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstdint>

class Database
{
  public:
    using dbConnection = std::shared_ptr<pqxx::connection>;

    Database(const std::string& user, const std::string& name, const std::string& pass, uint16_t poolSize);
    ~Database();

  private:
    friend class ConnectionGuard;

    dbConnection acquireConnection();
    void releaseConnection(dbConnection conn);

    dbConnection prepareDB(dbConnection conn);

    std::queue<dbConnection> connPool;
    std::mutex mtx;
    std::condition_variable cv;

    const std::string connectionString;
};

class ConnectionGuard
{
  public:
    ConnectionGuard(Database& db) : db(db), conn(db.acquireConnection()) {};
    ~ConnectionGuard() { db.releaseConnection(conn); };
    pqxx::connection& get() { return *conn; }
    pqxx::connection* operator->() { return conn.get(); }
  private:
    Database& db;
    Database::dbConnection conn;
};


#endif
