#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <map>

class EntropyCheck {
public:
    static double calculate(const std::string& data) {
        if (data.empty()) return 0.0;
        
        std::map<char, int> freq;
        for (char c : data) freq[c]++;
        
        double entropy = 0.0;
        double len = static_cast<double>(data.length());
        
        for (auto const& [c, count] : freq) {
            double p = static_cast<double>(count) / len;
            entropy -= p * log2(p);
        }
        
        return entropy;
    }

    static bool is_suspicious(const std::string& data) {
        double e = calculate(data);
        // High entropy (> 3.5 for short strings) often indicates tokens or secrets
        return (data.length() > 8 && e > 3.5);
    }
};

// Test entry point (not used in main fuzzer build)
/*
int main() {
    std::string test = "AIzaSyB-1234567890abcdef";
    std::cout << "Entropy: " << EntropyCheck::calculate(test) << std::endl;
    return 0;
}
*/
