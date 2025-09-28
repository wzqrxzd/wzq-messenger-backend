#ifndef ENV_UTILS_HXX
#define ENV_UTILS_HXX

#include <string>

namespace env_utils {
  void loadEnvFile(const std::string& filename = ".env");
  std::string getEnvVar(const char* key);
}

#endif
