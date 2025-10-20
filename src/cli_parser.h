#pragma once
#include <string>
#include <vector>
#include <map>

struct AnalysisConfig {
    std::string target_binary;
    std::vector<std::string> cli_args;
    std::map<std::string, std::string> env_vars;
    std::string output_format = "json";
    int verbosity_level = 0;
    bool help_requested = false;
    int timeout_seconds = 60;
    int max_instructions = 10000;
};

class CliParser {
public:
    AnalysisConfig parse(int argc, char* argv[]);
    void print_help() const;
    void print_usage() const;
};