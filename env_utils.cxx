#include "env_utils.hxx"
#include <fstream>
#include <spdlog/spdlog.h>

void env_utils::loadEnvFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
      spdlog::error("Failed open file({})", filename);
      return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t equalPos = line.find('=');
        if (equalPos == std::string::npos) continue;

        std::string key = line.substr(0, equalPos);
        std::string value = line.substr(equalPos + 1);

        if (!key.empty() && !value.empty()) {
            setenv(key.c_str(), value.c_str(), 1);
        }
    }
}

std::string env_utils::getEnvVar(const char* key) {
    const char* value = std::getenv(key);
    if (!value) {
        throw std::runtime_error(std::string("Missing environment variable: ") + key);
    }
    return value;
}
