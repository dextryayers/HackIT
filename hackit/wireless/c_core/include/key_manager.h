#pragma once

#include <cstdint>
#include <string>
#include <map>
#include <vector>

#ifdef _WIN32
#define KM_API __declspec(dllexport)
#else
#define KM_API
#endif

class KeyManager {
public:
    void AddKey(const std::string& bssid, const std::string& ssid, const std::string& psk);
    std::string LookupKey(const std::string& bssid, const std::string& ssid);
    bool HasKey(const std::string& bssid, const std::string& ssid);
    void SaveDatabase(const std::string& path);
    void LoadDatabase(const std::string& path);
    void Clear();

private:
    std::map<std::pair<std::string, std::string>, std::string> keys_;
};

extern "C" {
    KM_API void* key_manager_create();
    KM_API void key_manager_destroy(void* handle);
    KM_API void key_manager_add_key(void* handle, const char* bssid, const char* ssid, const char* psk);
    KM_API const char* key_manager_lookup_key(void* handle, const char* bssid, const char* ssid);
    KM_API int key_manager_has_key(void* handle, const char* bssid, const char* ssid);
    KM_API void key_manager_save(void* handle, const char* path);
    KM_API void key_manager_load(void* handle, const char* path);
    KM_API void key_manager_clear(void* handle);
}
