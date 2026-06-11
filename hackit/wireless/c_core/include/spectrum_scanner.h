#ifndef HACKIT_SPECTRUM_SCANNER_H
#define HACKIT_SPECTRUM_SCANNER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HACKIT_BAND_2_4GHZ 0
#define HACKIT_BAND_5GHZ   1

int  hackit_spectrum_scan_channels(const char* iface,
                                   int* channels_out,
                                   int* rssi_out,
                                   int  max_results);

int  hackit_spectrum_find_busy(const char* iface, int band);

int  hackit_spectrum_find_silent(const char* iface, int band);

bool hackit_spectrum_channel_utilization(const char* iface, int channel,
                                         float* out_utilization);

#ifdef __cplusplus
}
#endif

#endif // HACKIT_SPECTRUM_SCANNER_H
