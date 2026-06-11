#include "key_manager.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

void KeyManager::AddKey(const std::string& bssid, const std::string& ssid, const std::string& psk) {
    auto key = std::make_pair(bssid, ssid);
    keys_[key] = psk;
}

std::string KeyManager::LookupKey(const std::string& bssid, const std::string& ssid) {
    auto key = std::make_pair(bssid, ssid);
    auto it = keys_.find(key);
    if (it != keys_.end())
        return it->second;
    return "";
}

bool KeyManager::HasKey(const std::string& bssid, const std::string& ssid) {
    return keys_.find(std::make_pair(bssid, ssid)) != keys_.end();
}

void KeyManager::SaveDatabase(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open())
        return;

    // Simple JSON-like serialization
    file << "{\n";
    bool first = true;
    for (const auto& entry : keys_) {
        if (!first)
            file << ",\n";
        first = false;
        file << "  \"" << entry.first.first << "|" << entry.first.second << "\": \"" << entry.second << "\"";
    }
    file << "\n}\n";
    file.close();
}

void KeyManager::LoadDatabase(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        return;

    keys_.clear();
    std::string line;
    while (std::getline(file, line)) {
        // Parse "bssid|ssid": "psk"
        auto quote1 = line.find('"');
        if (quote1 == std::string::npos) continue;
        auto quote2 = line.find('"', quote1 + 1);
        if (quote2 == std::string::npos) continue;
        auto keyPart = line.substr(quote1 + 1, quote2 - quote1 - 1);
        auto pipePos = keyPart.find('|');
        if (pipePos == std::string::npos) continue;
        std::string bssid = keyPart.substr(0, pipePos);
        std::string ssid = keyPart.substr(pipePos + 1);

        auto colon = line.find(':', quote2 + 1);
        if (colon == std::string::npos) continue;
        auto quote3 = line.find('"', colon + 1);
        if (quote3 == std::string::npos) continue;
        auto quote4 = line.find('"', quote3 + 1);
        if (quote4 == std::string::npos) continue;
        std::string psk = line.substr(quote3 + 1, quote4 - quote3 - 1);

        keys_[std::make_pair(bssid, ssid)] = psk;
    }
    file.close();
}

void KeyManager::Clear() {
    keys_.clear();
}

// C API
extern "C" {

KM_API void* key_manager_create() {
    return new KeyManager();
}

KM_API void key_manager_destroy(void* handle) {
    delete static_cast<KeyManager*>(handle);
}

KM_API void key_manager_add_key(void* handle, const char* bssid, const char* ssid, const char* psk) {
    if (!handle || !bssid || !ssid || !psk) return;
    static_cast<KeyManager*>(handle)->AddKey(bssid, ssid, psk);
}

KM_API const char* key_manager_lookup_key(void* handle, const char* bssid, const char* ssid) {
    if (!handle || !bssid || !ssid) return "";
    static std::string result;
    result = static_cast<KeyManager*>(handle)->LookupKey(bssid, ssid);
    return result.c_str();
}

KM_API int key_manager_has_key(void* handle, const char* bssid, const char* ssid) {
    if (!handle || !bssid || !ssid) return 0;
    return static_cast<KeyManager*>(handle)->HasKey(bssid, ssid) ? 1 : 0;
}

KM_API void key_manager_save(void* handle, const char* path) {
    if (!handle || !path) return;
    static_cast<KeyManager*>(handle)->SaveDatabase(path);
}

KM_API void key_manager_load(void* handle, const char* path) {
    if (!handle || !path) return;
    static_cast<KeyManager*>(handle)->LoadDatabase(path);
}

KM_API void key_manager_clear(void* handle) {
    if (!handle) return;
    static_cast<KeyManager*>(handle)->Clear();
}

}
