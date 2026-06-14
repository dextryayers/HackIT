#include "cpp_bridge.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <sstream>
#include <map>
#include <atomic>
#include <functional>
#include <cstring>
#include <cstdio>

struct AttackTask {
    std::string id;
    std::string name;
    std::string params;
    std::atomic<bool> running{false};
    std::atomic<bool> finished{false};
    int packets_sent{0};
    int packets_received{0};
    double progress{0.0};
    std::string status{"idle"};
    std::string details;
    std::thread worker;
};

static std::mutex g_mutex;
static std::map<std::string, AttackTask> g_tasks;
static int g_next_id = 0;

static std::string json_escape(const std::string &s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}

static std::string build_json_status(const AttackTask &t) {
    std::ostringstream os;
    os << "{"
       << "\"id\":\"" << json_escape(t.id) << "\","
       << "\"name\":\"" << json_escape(t.name) << "\","
       << "\"status\":\"" << json_escape(t.status) << "\","
       << "\"progress\":" << t.progress << ","
       << "\"packets_sent\":" << t.packets_sent << ","
       << "\"packets_received\":" << t.packets_received << ","
       << "\"details\":\"" << json_escape(t.details) << "\""
       << "}";
    return os.str();
}

extern "C" const char* orchestrator_launch(const char* name, const char* params_json) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::string id = "task_" + std::to_string(++g_next_id);
    AttackTask task;
    task.id = id;
    task.name = name ? name : "unknown";
    task.params = params_json ? params_json : "{}";
    task.running = true;
    task.status = "launching";
    auto it = g_tasks.emplace(id, std::move(task)).first;
    it->second.worker = std::thread([&itref = it->second, name = it->second.name, params = it->second.params]() {
        itref.status = "running";
        itref.details = "Starting " + name + " with params: " + params;
        int steps = 20;
        for (int i = 0; i < steps; i++) {
            if (!itref.running) {
                itref.status = "stopped";
                itref.details = "Attack stopped by user";
                itref.finished = true;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            itref.packets_sent += 10;
            itref.packets_received += rand() % 10;
            itref.progress = (double)(i + 1) / steps * 100.0;
        }
        itref.status = "completed";
        itref.details = "Attack " + std::string(name) + " finished successfully";
        itref.progress = 100.0;
        itref.finished = true;
    });
    it->second.worker.detach();
    static std::string result;
    result = "{\"id\":\"" + id + "\",\"status\":\"launching\"}";
    return result.c_str();
}

extern "C" int orchestrator_stop(const char* id) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_tasks.find(id ? id : "");
    if (it == g_tasks.end()) return -1;
    it->second.running = false;
    it->second.status = "stopping";
    return 0;
}

extern "C" const char* orchestrator_get_status(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    static std::string result;
    std::ostringstream os;
    os << "[";
    bool first = true;
    for (const auto &pair : g_tasks) {
        if (!first) os << ",";
        os << build_json_status(pair.second);
        first = false;
    }
    os << "]";
    result = os.str();
    return result.c_str();
}

extern "C" const char* orchestrator_get_results(const char* id) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_tasks.find(id ? id : "");
    if (it == g_tasks.end()) return "{\"error\":\"task not found\"}";
    static std::string result;
    result = build_json_status(it->second);
    return result.c_str();
}

extern "C" const char* orchestrator_multi_engine(const char* engines_json, const char* params_json) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::string id = "multi_" + std::to_string(++g_next_id);
    AttackTask task;
    task.id = id;
    task.name = "multi_engine";
    task.params = engines_json ? engines_json : "[]";
    task.running = true;
    task.status = "coordinating";
    auto it = g_tasks.emplace(id, std::move(task)).first;
    it->second.worker = std::thread([&itref = it->second, eng = it->second.params]() {
        itref.status = "orchestrating";
        itref.details = "Coordinating engines: " + eng;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        itref.packets_sent = 100;
        itref.packets_received = 85;
        itref.progress = 100.0;
        itref.status = "completed";
        itref.details = "Multi-engine orchestration complete";
        itref.finished = true;
    });
    it->second.worker.detach();
    static std::string result;
    result = "{\"id\":\"" + id + "\",\"status\":\"coordinating\"}";
    return result.c_str();
}
