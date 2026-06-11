#ifndef HACKIT_EAPOL_ANALYZER_H
#define HACKIT_EAPOL_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HACKIT_EAPOL_ANONCE_LEN  32
#define HACKIT_EAPOL_SNONCE_LEN  32
#define HACKIT_EAPOL_MIC_LEN     16

typedef struct {
    int  step;
    bool has_mic;
    bool has_install;
    uint16_t key_info;
    uint8_t  anonce[HACKIT_EAPOL_ANONCE_LEN];
    uint8_t  snonce[HACKIT_EAPOL_SNONCE_LEN];
    uint8_t  mic[HACKIT_EAPOL_MIC_LEN];
    int  key_data_len;
} EapolResult;

bool hackit_eapol_parse_frame(const uint8_t* frame, int frame_len, EapolResult* out);

int  hackit_eapol_detect_step(const uint8_t* frame, int frame_len);

bool hackit_eapol_extract_anonce(const uint8_t* frame, int frame_len,
                                 uint8_t* out_anonce, int* out_len);

bool hackit_eapol_extract_snonce(const uint8_t* frame, int frame_len,
                                 uint8_t* out_snonce, int* out_len);

bool hackit_eapol_extract_mic(const uint8_t* frame, int frame_len,
                              uint8_t* out_mic, int* out_len);

bool hackit_eapol_validate_integrity(const uint8_t* frame, int frame_len);

#ifdef __cplusplus
}
#endif

#endif // HACKIT_EAPOL_ANALYZER_H
