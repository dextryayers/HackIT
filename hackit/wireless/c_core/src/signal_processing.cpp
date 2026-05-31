#include "signal_processing.h"
#include <cmath>
#include <vector>
#include <numeric>

extern "C" {

int hackit_dsp_smooth_rssi(int* raw_samples, int num_samples) {
    if (!raw_samples || num_samples <= 0) return -100;
    
    std::vector<int> samples(raw_samples, raw_samples + num_samples);
    
    // Very basic Kalman filter 1D approximation logic to smooth out Wi-Fi signal jumping
    double q = 0.1; // process noise covariance
    double r = 0.1; // measurement noise covariance
    double p = 1.0; // estimation error covariance
    double k = 0.0; // kalman gain
    double x = samples[0]; // value
    
    for (int i = 1; i < num_samples; ++i) {
        p = p + q;
        k = p / (p + r);
        x = x + k * (samples[i] - x);
        p = (1 - k) * p;
    }
    
    return static_cast<int>(std::round(x));
}

double hackit_dsp_calculate_proximity(int rssi_dbm, int tx_power) {
    // Free Space Path Loss (FSPL) approximation
    // d = 10 ^ ((tx_power - rssi) / (10 * n)) where n is signal path loss exponent (2.0 to 4.0)
    // we use a generic n=2.7 for indoor environments
    if (rssi_dbm == 0) return -1.0; 
    
    double ratio = (tx_power - rssi_dbm) / (10.0 * 2.7);
    double distance_meters = std::pow(10.0, ratio);
    
    // Convert to a percentage proxy (0 to 100) where 100 is touching the router
    double prox = 100.0 - (distance_meters * 1.5);
    if (prox < 0.0) prox = 0.0;
    if (prox > 100.0) prox = 100.0;
    
    return prox;
}

}
