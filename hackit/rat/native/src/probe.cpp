// /proc and inotify probes. Read-only, bounded, no shell-outs: the point is to
// answer "what is this device doing" without spawning anything a monitor sees.
#include "hackit.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace hackit {
namespace {

std::string read_file(const std::string &path, size_t cap = 256 * 1024) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::string();
    std::ostringstream out;
    out << in.rdbuf();
    std::string data = out.str();
    if (data.size() > cap) data.resize(cap);
    return data;
}

std::vector<std::string> lines(const std::string &text) {
    std::vector<std::string> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) out.push_back(line);
    return out;
}

std::string trim(const std::string &value) {
    size_t begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return std::string();
    size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

uint32_t hex_value(const std::string &text) {
    uint32_t value = 0;
    for (char c : text) {
        value <<= 4;
        if (c >= '0' && c <= '9') value |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') value |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') value |= (uint32_t)(c - 'A' + 10);
    }
    return value;
}

bool contains(const std::string &haystack, const char *needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

std::string json_escape(const std::string &text) {
    std::string out;
    out.reserve(text.size() + 16);
    for (unsigned char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

std::string hex(const uint8_t *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0x0f];
    }
    return out;
}

std::string probe_maps() {
    std::string maps = read_file("/proc/self/maps");
    const char *markers[] = {"frida",      "gum-js-loop", "gmain",   "linjector",
                             "xposed",     "substrate",   "riru",    "zygisk",
                             "magisk",     "libmemtrack", "hackit"};
    std::string out = "{\"markers\":[";
    bool first = true;
    int anon_exec = 0;
    int total = 0;
    for (const std::string &line : lines(maps)) {
        total++;
        bool exec = line.find("r-xp") != std::string::npos || line.find("rwxp") != std::string::npos;
        bool file_backed = line.find('/') != std::string::npos;
        if (exec && !file_backed) anon_exec++;
        for (const char *marker : markers) {
            if (contains(line, marker)) {
                if (!first) out += ',';
                first = false;
                std::string entry = "{\"marker\":\"";
                entry += marker;
                entry += "\",\"line\":\"";
                entry += json_escape(trim(line));
                entry += "\"}";
                out += entry;
                break;
            }
        }
    }
    char tail[160];
    std::snprintf(tail, sizeof(tail), "],\"maps\":%d,\"anon_exec\":%d}", total, anon_exec);
    return out + tail;
}

std::string probe_status() {
    std::string status = read_file("/proc/self/status", 8192);
    std::string tracer = "0";
    std::string seccomp = "0";
    std::string no_new_privs = "0";
    for (const std::string &line : lines(status)) {
        if (line.rfind("TracerPid:", 0) == 0) tracer = trim(line.substr(10));
        if (line.rfind("Seccomp:", 0) == 0) seccomp = trim(line.substr(8));
        if (line.rfind("NoNewPrivs:", 0) == 0) no_new_privs = trim(line.substr(11));
    }
    char pid[32];
    std::snprintf(pid, sizeof(pid), "%d", (int)getpid());
    char ppid[32];
    std::snprintf(ppid, sizeof(ppid), "%d", (int)getppid());
    std::string selinux = trim(read_file("/sys/fs/selinux/enforce", 64));
    if (selinux.empty()) selinux = trim(read_file("/proc/self/attr/current", 256));
    std::string out = "{\"pid\":";
    out += pid;
    out += ",\"ppid\":";
    out += ppid;
    out += ",\"tracer\":";
    out += json_escape(tracer);
    out += ",\"seccomp\":";
    out += json_escape(seccomp);
    out += ",\"no_new_privs\":";
    out += json_escape(no_new_privs);
    out += ",\"selinux\":";
    out += json_escape(selinux);
    out += ",\"uid\":";
    out += std::to_string((long)getuid());
    out += ",\"kernel\":\"";
    out += json_escape(trim(read_file("/proc/version", 512)));
    out += "\"}";
    return out;
}

std::string probe_proc_list() {
    DIR *dir = opendir("/proc");
    if (dir == nullptr) return "{\"processes\":0}";
    std::vector<std::pair<std::string, std::string>> found;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        char *end = nullptr;
        long pid = std::strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || pid <= 0) continue;
        std::string comm = trim(read_file(std::string("/proc/") + entry->d_name + "/comm", 128));
        std::string cmdline = read_file(std::string("/proc/") + entry->d_name + "/cmdline", 512);
        for (char &c : cmdline) {
            if (c == '\0') c = ' ';
        }
        if (comm.empty() && cmdline.empty()) continue;
        found.emplace_back(comm, trim(cmdline));
        if (found.size() >= 400) break;
    }
    closedir(dir);
    std::string out = "{\"processes\":" + std::to_string(found.size()) + ",\"list\":[";
    for (size_t i = 0; i < found.size(); ++i) {
        if (i) out += ',';
        out += "{\"comm\":\"";
        out += json_escape(found[i].first);
        out += "\",\"cmd\":\"";
        out += json_escape(found[i].second.substr(0, 200));
        out += "\"}";
    }
    out += "]}";
    return out;
}

std::string probe_net() {
    const char *files[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
    std::string out = "{\"sockets\":[";
    bool first = true;
    int listeners = 0;
    int total = 0;
    for (const char *path : files) {
        std::string text = read_file(path, 128 * 1024);
        for (const std::string &line : lines(text)) {
            size_t indent = line.find_first_not_of(" \t");
            if (line.size() < 40 || indent == std::string::npos || line.compare(indent, 2, "sl") == 0) continue;
            std::istringstream in(line);
            std::string sl, local, remote, state;
            in >> sl >> local >> remote >> state;
            if (local.empty() || state.empty()) continue;
            total++;
            if (state == "0A") listeners++;
            std::string ip = local.substr(0, local.find(':'));
            std::string port = local.substr(local.find(':') + 1);
            std::string rendered;
            if (ip.size() == 8) {
                char buf[32];
                unsigned a = (unsigned)hex_value(ip.substr(6, 2));
                unsigned b = (unsigned)hex_value(ip.substr(4, 2));
                unsigned c = (unsigned)hex_value(ip.substr(2, 2));
                unsigned d = (unsigned)hex_value(ip.substr(0, 2));
                std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a, b, c, d);
                rendered = buf;
            } else {
                rendered = ip;
            }
            if (!first) out += ',';
            first = false;
            char item[256];
            std::snprintf(item, sizeof(item), "{\"local\":\"%s\",\"port\":%u,\"state\":\"%s\"}",
                          rendered.c_str(), (unsigned)hex_value(port), state.c_str());
            out += item;
            if (total >= 200) break;
        }
        if (total >= 200) break;
    }
    char tail[96];
    std::snprintf(tail, sizeof(tail), "],\"total\":%d,\"listeners\":%d}", total, listeners);
    return out + tail;
}

std::string probe_mounts() {
    std::string text = read_file("/proc/mounts", 128 * 1024);
    std::string out = "{\"mounts\":[";
    bool first = true;
    int count = 0;
    for (const std::string &line : lines(text)) {
        std::istringstream in(line);
        std::string source, target, type, options;
        in >> source >> target >> type >> options;
        if (target.empty()) continue;
        count++;
        if (!first) out += ',';
        first = false;
        out += "{\"source\":\"";
        out += json_escape(source);
        out += "\",\"target\":\"";
        out += json_escape(target);
        out += "\",\"type\":\"";
        out += json_escape(type);
        out += "\",\"options\":\"";
        out += json_escape(options);
        out += "\"}";
        if (count >= 120) break;
    }
    char tail[64];
    std::snprintf(tail, sizeof(tail), "],\"count\":%d}", count);
    return out + tail;
}

std::string probe_cpu() {
    std::string info = read_file("/proc/cpuinfo", 128 * 1024);
    std::string model;
    int cores = 0;
    for (const std::string &line : lines(info)) {
        if (line.rfind("processor", 0) == 0) cores++;
        if (model.empty() && line.rfind("model name", 0) == 0) {
            model = trim(line.substr(line.find(':') + 1));
        }
    }
    std::string mem = read_file("/proc/meminfo", 8192);
    long total_kb = 0;
    long free_kb = 0;
    for (const std::string &line : lines(mem)) {
        if (line.rfind("MemTotal:", 0) == 0) total_kb = std::strtol(line.c_str() + 9, nullptr, 10);
        if (line.rfind("MemAvailable:", 0) == 0) free_kb = std::strtol(line.c_str() + 14, nullptr, 10);
    }
    char out[1024];
    std::snprintf(out, sizeof(out),
                  "{\"model\":\"%s\",\"cores\":%d,\"mem_total_kb\":%ld,\"mem_free_kb\":%ld,"
                  "\"load\":\"%s\",\"uptime\":\"%s\"}",
                  json_escape(model).c_str(), cores, total_kb, free_kb,
                  json_escape(trim(read_file("/proc/loadavg", 128))).c_str(),
                  json_escape(trim(read_file("/proc/uptime", 64))).c_str());
    return out;
}

std::string probe_snapshot() {
    std::string out = "{\"op\":\"probe\",\"data\":{\"maps\":";
    out += probe_maps();
    out += ",\"status\":";
    out += probe_status();
    out += ",\"net\":";
    out += probe_net();
    out += ",\"mounts\":";
    out += probe_mounts();
    out += ",\"cpu\":";
    out += probe_cpu();
    out += "}}";
    return out;
}

// ------------------------------------------------------------------ inotify

struct Watch {
    int fd = -1;
    std::vector<std::pair<int, std::string>> paths;
};

std::vector<Watch> g_watches;

bool watch_add(const std::string &directory) {
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return false;
    int wd = inotify_add_watch(fd, directory.c_str(),
                               IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE | IN_MODIFY);
    if (wd < 0) {
        close(fd);
        return false;
    }
    Watch watch;
    watch.fd = fd;
    watch.paths.emplace_back(wd, directory);
    g_watches.push_back(watch);
    return true;
}

bool watch_start(const std::string &directory) {
    watch_stop();
    return watch_add(directory);
}

void watch_stop() {
    for (Watch &watch : g_watches) {
        if (watch.fd >= 0) close(watch.fd);
    }
    g_watches.clear();
}

std::string watch_drain() {
    std::string out = "[";
    bool first = true;
    char buffer[16 * 1024] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (Watch &watch : g_watches) {
        for (;;) {
            ssize_t length = read(watch.fd, buffer, sizeof(buffer));
            if (length <= 0) break;
            for (char *ptr = buffer; ptr < buffer + length;) {
                struct inotify_event *event = (struct inotify_event *)ptr;
                std::string path = watch.paths.empty() ? std::string() : watch.paths[0].second;
                for (auto &entry : watch.paths) {
                    if (entry.first == event->wd) path = entry.second;
                }
                if (!first) out += ',';
                first = false;
                std::string name = event->len > 0 ? std::string(event->name) : path;
                char item[1024];
                std::snprintf(item, sizeof(item), "{\"mask\":%u,\"path\":\"%s\",\"name\":\"%s\"}",
                              (unsigned)event->mask, json_escape(path).c_str(), json_escape(name).c_str());
                out += item;
                ptr += sizeof(struct inotify_event) + event->len;
            }
            if (out.size() > 60 * 1024) break;
        }
    }
    out += "]";
    return out;
}

}  // namespace hackit