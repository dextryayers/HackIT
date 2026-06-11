#include "channel_hopper.h"
#include "adapter_detection.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define HACKIT_MUTEX CRITICAL_SECTION
#define HACKIT_MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define HACKIT_MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define HACKIT_MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#define HACKIT_MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define HACKIT_THREAD HANDLE
#define HACKIT_THREAD_CREATE(t, fn, arg) (*(t) = CreateThread(NULL, 0, (fn), (arg), 0, NULL)) != NULL
#define HACKIT_THREAD_JOIN(t) WaitForSingleObject((t), INFINITE)
#define HACKIT_THREAD_EXIT DWORD WINAPI
#define HACKIT_SLEEP_MS(ms) Sleep((DWORD)(ms))
#else
#include <unistd.h>
#include <pthread.h>
#define HACKIT_MUTEX pthread_mutex_t
#define HACKIT_MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define HACKIT_MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define HACKIT_MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#define HACKIT_MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define HACKIT_THREAD pthread_t
#define HACKIT_THREAD_CREATE(t, fn, arg) pthread_create(&(t), NULL, (fn), (arg)) == 0
#define HACKIT_THREAD_JOIN(t) pthread_join((t), NULL)
#define HACKIT_THREAD_EXIT void*
#define HACKIT_SLEEP_MS(ms) usleep((useconds_t)(ms) * 1000)
#endif

/* ------------------------------------------------------------------ */

typedef struct {
    char iface[64];
    int channels[HACKIT_MAX_CHANNELS];
    int channel_count;
    volatile int current_channel;
    int dwell_ms;
    volatile int running;
    bool include_5ghz;
    int initialized;
    HACKIT_MUTEX lock;
    HACKIT_THREAD thread;
} hopper_state_t;

static hopper_state_t g_hopper;

static const int DEFAULT_24GHZ[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
static const int DEFAULT_5GHZ[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165};

/* ------------------------------------------------------------------ */

#ifdef _WIN32
static HACKIT_THREAD_EXIT hopper_thread_func(LPVOID arg) {
    (void)arg;
#else
static HACKIT_THREAD_EXIT hopper_thread_func(void* arg) {
    (void)arg;
#endif

    while (g_hopper.running) {
        for (int i = 0; i < g_hopper.channel_count; i++) {
            if (!g_hopper.running)
                break;

            int ch = g_hopper.channels[i];

            HACKIT_MUTEX_LOCK(g_hopper.lock);
            g_hopper.current_channel = ch;
            HACKIT_MUTEX_UNLOCK(g_hopper.lock);

            hackit_c_set_channel(g_hopper.iface, ch);

            HACKIT_SLEEP_MS(g_hopper.dwell_ms);
        }
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* ------------------------------------------------------------------ */

int hackit_channel_hopper_init(const char* iface) {
    if (!iface)
        return -1;

    memset(&g_hopper, 0, sizeof(g_hopper));
    strncpy(g_hopper.iface, iface, sizeof(g_hopper.iface) - 1);
    g_hopper.iface[sizeof(g_hopper.iface) - 1] = '\0';
    g_hopper.dwell_ms = HACKIT_DEFAULT_DWELL_MS;
    g_hopper.running = 0;
    g_hopper.current_channel = 0;
    g_hopper.channel_count = 0;
    g_hopper.include_5ghz = false;

    HACKIT_MUTEX_INIT(g_hopper.lock);
    g_hopper.initialized = 1;

    return 0;
}

/* ------------------------------------------------------------------ */

int hackit_channel_hopper_set_channels(const int* channels, int count) {
    if (!g_hopper.initialized)
        return -1;

    if (!channels || count <= 0 || count > HACKIT_MAX_CHANNELS)
        return -1;

    HACKIT_MUTEX_LOCK(g_hopper.lock);
    g_hopper.channel_count = count;
    memcpy(g_hopper.channels, channels, (size_t)count * sizeof(int));
    HACKIT_MUTEX_UNLOCK(g_hopper.lock);

    return 0;
}

/* ------------------------------------------------------------------ */

int hackit_channel_hopper_start(int dwell_ms, bool include_5ghz) {
    if (!g_hopper.initialized)
        return -1;

    if (g_hopper.running)
        return -1;

    g_hopper.running = 1;
    g_hopper.include_5ghz = include_5ghz;

    if (dwell_ms > 0)
        g_hopper.dwell_ms = dwell_ms;

    if (g_hopper.channel_count == 0) {
        int count = 0;

        for (size_t i = 0; i < sizeof(DEFAULT_24GHZ) / sizeof(DEFAULT_24GHZ[0]) && count < HACKIT_MAX_CHANNELS; i++)
            g_hopper.channels[count++] = DEFAULT_24GHZ[i];

        if (include_5ghz) {
            for (size_t i = 0; i < sizeof(DEFAULT_5GHZ) / sizeof(DEFAULT_5GHZ[0]) && count < HACKIT_MAX_CHANNELS; i++)
                g_hopper.channels[count++] = DEFAULT_5GHZ[i];
        }

        g_hopper.channel_count = count;
    }

#ifdef _WIN32
    g_hopper.thread = CreateThread(NULL, 0, hopper_thread_func, NULL, 0, NULL);
    if (!g_hopper.thread) {
        g_hopper.running = 0;
        fprintf(stderr, "[HOPPER] Failed to create thread\n");
        return -1;
    }
#else
    if (pthread_create(&g_hopper.thread, NULL, hopper_thread_func, NULL) != 0) {
        g_hopper.running = 0;
        fprintf(stderr, "[HOPPER] Failed to create thread\n");
        return -1;
    }
#endif

    printf("[HOPPER] Started hopping on '%s' (%d channels, %d ms dwell)%s\n",
           g_hopper.iface, g_hopper.channel_count, g_hopper.dwell_ms,
           include_5ghz ? " +5GHz" : "");

    return 0;
}

/* ------------------------------------------------------------------ */

int hackit_channel_hopper_stop(void) {
    if (!g_hopper.initialized)
        return -1;

    if (!g_hopper.running)
        return 0;

    g_hopper.running = 0;

#ifdef _WIN32
    WaitForSingleObject(g_hopper.thread, 5000);
    CloseHandle(g_hopper.thread);
#else
    pthread_join(g_hopper.thread, NULL);
#endif

    printf("[HOPPER] Stopped hopping on '%s'\n", g_hopper.iface);
    return 0;
}

/* ------------------------------------------------------------------ */

int hackit_get_current_channel(void) {
    if (!g_hopper.initialized)
        return 0;

    int ch;
    HACKIT_MUTEX_LOCK(g_hopper.lock);
    ch = g_hopper.current_channel;
    HACKIT_MUTEX_UNLOCK(g_hopper.lock);

    return ch;
}
