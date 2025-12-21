#ifndef USER_FIELDS_HXX
#define USER_FIELDS_HXX

#include <optional>
#include <string>

struct UserFields {
  std::optional<std::string> name;
  std::optional<std::string> username;
  std::optional<std::string> password;
  std::optional<std::string> description;
  std::optional<int> id;
};

#endif
