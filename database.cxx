#include "database.hxx"
#include <memory>
#include <cstdint>
#include <mutex>
#include <stdexcept>

Database::Database(const std::string& user, const std::string& name, const std::string& pass, const uint16_t poolSize)
  : connectionString(
  "dbname=" + name +
  " user=" + user +
  " password=" + pass +
  " host=db port=5432")
{
  for (int i{0}; i<poolSize; i++)
    connPool.push(prepareDB(std::make_shared<pqxx::connection>(connectionString)));
}

Database::~Database() = default;

Database::dbConnection Database::acquireConnection()
{
  std::unique_lock<std::mutex> lock(mtx);
  cv.wait(lock, [&] { return !connPool.empty(); });

  auto conn = connPool.front();
  connPool.pop();
  return conn;
}

void Database::releaseConnection(Database::dbConnection conn)
{
  {
    std::unique_lock<std::mutex> lock(mtx);
    connPool.push(std::move(conn));
  }
  cv.notify_all();
}

Database::dbConnection Database::prepareDB(Database::dbConnection conn)
{
  conn->prepare("insert_user", "INSERT INTO users(username, password_hash, name, description) VALUES($1, $2, $3, $4)");
  conn->prepare("find_user", "SELECT password_hash FROM users WHERE username=$1");


  conn->prepare("insert_chat", "INSERT INTO chats(name) VALUES($1) RETURNING id");
  conn->prepare("insert_chat_member", "INSERT INTO chat_members(chat_id, user_id) VALUES($1, $2)");
  conn->prepare("find_user_by_username", "SELECT id FROM users WHERE username=$1");
  conn->prepare(
    "insert_message",
    "INSERT INTO messages(chat_id, sender_id, content) VALUES($1, $2, $3) RETURNING id"
  );
  conn->prepare("delete_message",
    "DELETE FROM messages "
    "WHERE id = $1"
  );

  conn->prepare("delete_chat",
    "DELETE FROM chats WHERE id = $1"
  );

  conn->prepare("delete_chat_members",
    "DELETE FROM chat_members WHERE chat_id = $1"
  );

  conn->prepare("delete_chat_messages",
    "DELETE FROM messages WHERE chat_id = $1"
  );

  conn->prepare("check_user_in_chat",
    "SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id = $2"
  );

  conn->prepare("find_user_by_message",
    "SELECT sender_id FROM messages WHERE id=$1"
  );

  conn->prepare(
    "get_user_chats",
    "SELECT c.id, c.name FROM chats c "
    "JOIN chat_members cm ON c.id = cm.chat_id "
    "WHERE cm.user_id = $1"
  );

  // conn->prepare(
  //   "get_chat_messages",
  //   "SELECT m.id, m.sender_id, m.content, m.read "
  //   "FROM messages m "
  //   "WHERE m.chat_id = $1 "
  //   "ORDER BY m.id ASC"
  // );

  conn->prepare(
    "get_chat_messages",
    "SELECT m.id, m.sender_id, u.username AS sender_name, m.content, m.read "
    "FROM messages m "
    "JOIN users u ON m.sender_id = u.id "
    "WHERE m.chat_id = $1 "
    "ORDER BY m.id ASC"
  );

  conn->prepare(
      "get_username_by_id",
      "SELECT username FROM users WHERE id = $1"
  );

  conn->prepare(
      "get_user_by_id",
      "SELECT username, name, description FROM users WHERE id = $1"
  );

  conn->prepare(
      "get_chatname_by_id",
      "SELECT name FROM chats WHERE id = $1"
  );

  conn->prepare(
      "check_exists_chat",
      "SELECT chat_id FROM chat_members WHERE user_id IN ($1, $2) GROUP BY chat_id HAVING COUNT(DISTINCT user_id) = 2"
  );

  return conn;
}
