#ifndef HACKIT_CHANNEL_HOPPER_H
#define HACKIT_CHANNEL_HOPPER_H

#include <stdbool.h>
#include <stdint.h>

#define HACKIT_MAX_CHANNELS 64
#define HACKIT_DEFAULT_DWELL_MS 200
#define HACKIT_DEFAULT_24GHZ_CHANNELS {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

int hackit_channel_hopper_init(const char* iface);
int hackit_channel_hopper_set_channels(const int* channels, int count);
int hackit_channel_hopper_start(int dwell_ms, bool include_5ghz);
int hackit_channel_hopper_stop(void);
int hackit_get_current_channel(void);

#endif // HACKIT_CHANNEL_HOPPER_H
