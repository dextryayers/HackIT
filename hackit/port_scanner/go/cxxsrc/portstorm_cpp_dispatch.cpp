#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
extern int advanced_scanner_main(int argc, char **argv);
extern int ai_pattern_analyzer_main(int argc, char **argv);
extern int anomaly_detector_main(int argc, char **argv);
extern int correlation_engine_main(int argc, char **argv);
extern int deep_analyzer_main(int argc, char **argv);
extern int deep_learning_analyzer_main(int argc, char **argv);
extern int exploit_detection_engine_main(int argc, char **argv);
extern int os_detect_main(int argc, char **argv);
extern int report_generator_main(int argc, char **argv);
extern int response_parser_main(int argc, char **argv);
extern int results_correlator_main(int argc, char **argv);
extern int risk_calculator_main(int argc, char **argv);
extern int service_classifier_main(int argc, char **argv);
extern int service_scanner_main(int argc, char **argv);
extern int stack_fingerprinter_main(int argc, char **argv);
extern int tls_analyzer_v2_main(int argc, char **argv);
extern int tls_forensic_analyzer_main(int argc, char **argv);
extern int tls_scanner_main(int argc, char **argv);
extern int vulnerability_scanner_main(int argc, char **argv);
extern int vuln_matcher_main(int argc, char **argv);
extern int vuln_matcher_v2_main(int argc, char **argv);

typedef int (*scanner_fn)(int, char **);
typedef struct { const char *name; scanner_fn fn; } ScannerEntry;

static const ScannerEntry SCANNERS[] = {
    {"advanced_scanner",       advanced_scanner_main},
    {"ai_pattern_analyzer",    ai_pattern_analyzer_main},
    {"anomaly_detector",       anomaly_detector_main},
    {"correlation_engine",     correlation_engine_main},
    {"deep_analyzer",          deep_analyzer_main},
    {"deep_learning_analyzer", deep_learning_analyzer_main},
    {"exploit_detection_engine", exploit_detection_engine_main},
    {"os_detect",              os_detect_main},
    {"report_generator",       report_generator_main},
    {"response_parser",        response_parser_main},
    {"results_correlator",     results_correlator_main},
    {"risk_calculator",        risk_calculator_main},
    {"service_classifier",     service_classifier_main},
    {"service_scanner",        service_scanner_main},
    {"stack_fingerprinter",    stack_fingerprinter_main},
    {"tls_analyzer_v2",        tls_analyzer_v2_main},
    {"tls_forensic_analyzer",  tls_forensic_analyzer_main},
    {"tls_scanner",            tls_scanner_main},
    {"vulnerability_scanner",  vulnerability_scanner_main},
    {"vuln_matcher",           vuln_matcher_main},
    {"vuln_matcher_v2",        vuln_matcher_v2_main},
    {NULL, NULL}
};

__attribute__((visibility("default")))
int portstorm_cpp_dispatch(const char *name, int argc, char **argv) {
    if (!name) return -1;
    for (const ScannerEntry *e = SCANNERS; e->name; e++) {
        if (std::strcmp(e->name, name) == 0) return e->fn(argc, argv);
    }
    std::fprintf(stderr, "Unknown C++ scanner: %s\n", name);
    return -1;
}

__attribute__((visibility("default")))
const char **portstorm_cpp_list_scanners(void) {
    static const char *names[24];
    int i = 0;
    for (const ScannerEntry *e = SCANNERS; e->name; e++) names[i++] = e->name;
    names[i] = NULL;
    return names;
}

__attribute__((visibility("default")))
int portstorm_cpp_scanner_count(void) {
    int n = 0;
    for (const ScannerEntry *e = SCANNERS; e->name; e++) n++;
    return n;
}
} // extern "C"
