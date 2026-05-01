/*
 * HackIT SQLi Data Dump Engine (C++)
 * Advanced parsing and reconstruction of data from SQLi responses.
 */

#include <iostream>
#include <string>
#include <vector>
#include <regex>

using namespace std;

class DataDumpEngine {
public:
    struct DumpedData {
        string table_name;
        vector<string> columns;
        vector<vector<string>> rows;
    };

    /**
     * Parse data from union-based responses
     */
    DumpedData parse_union_response(const string& html, const string& start_tag, const string& end_tag) {
        DumpedData data;
        regex re(start_tag + "(.*?)" + end_tag);
        auto words_begin = sregex_iterator(html.begin(), html.end(), re);
        auto words_end = sregex_iterator();

        for (sregex_iterator i = words_begin; i != words_end; ++i) {
            smatch match = *i;
            data.columns.push_back(match.str(1));
        }
        
        return data;
    }
};

extern "C" {
    #ifdef _WIN32
    __declspec(dllexport)
    #endif
    const char* extract_data_from_response(const char* html, const char* start_tag, const char* end_tag) {
        static string result;
        DataDumpEngine engine;
        auto data = engine.parse_union_response(html, start_tag, end_tag);
        
        result = "";
        for (const auto& col : data.columns) {
            result += col + ",";
        }
        
        return result.c_str();
    }
}
