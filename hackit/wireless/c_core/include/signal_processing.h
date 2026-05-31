#ifndef HACKIT_SIGNAL_PROCESSING_H
#define HACKIT_SIGNAL_PROCESSING_H

#ifdef __cplusplus
extern "C" {
#endif

// Performs a generic Fast Fourier Transform equivalent on raw RSSI samples
// returning the smoothed out DbM to eliminate jumping fluctuations.
int hackit_dsp_smooth_rssi(int* raw_samples, int num_samples);

// Advanced C++ vector math to triangulate proximity (0.0 to 100.0 scale) based on signal bounce
double hackit_dsp_calculate_proximity(int rssi_dbm, int tx_power);

#ifdef __cplusplus
}
#endif

#endif // HACKIT_SIGNAL_PROCESSING_H
