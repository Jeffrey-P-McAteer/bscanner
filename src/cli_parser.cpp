#include "cli_parser.h"
#include <iostream>
#include <stdexcept>
#include <cstring>

AnalysisConfig CliParser::parse(int argc, char* argv[]) {
    AnalysisConfig config;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            config.help_requested = true;
            return config;
        } else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value for output format");
            }
            config.output_format = argv[++i];
        } else if (arg == "-t" || arg == "--timeout") {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value for timeout");
            }
            config.timeout_seconds = std::stoi(argv[++i]);
        } else if (arg == "--env") {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value for environment variable");
            }
            std::string env_pair = argv[++i];
            size_t eq_pos = env_pair.find('=');
            if (eq_pos == std::string::npos) {
                throw std::runtime_error("Invalid environment variable format (use KEY=VALUE)");
            }
            config.env_vars[env_pair.substr(0, eq_pos)] = env_pair.substr(eq_pos + 1);
        } else if (arg == "--args") {
            i++;
            while (i < argc && argv[i][0] != '-') {
                config.cli_args.push_back(argv[i]);
                i++;
            }
            i--;
        } else if (arg[0] != '-') {
            if (config.target_binary.empty()) {
                config.target_binary = arg;
            } else {
                throw std::runtime_error("Multiple target binaries specified");
            }
        } else {
            throw std::runtime_error("Unknown option: " + arg);
        }
    }
    
    return config;
}

void CliParser::print_help() const {
    std::cout << "BScanner - Dynamic Binary Analysis Tool\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  bscanner [OPTIONS] <binary>\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -v, --verbose           Enable verbose output\n";
    std::cout << "  -o, --output FORMAT     Output format (json, xml, text) [default: json]\n";
    std::cout << "  -t, --timeout SECONDS   Analysis timeout in seconds [default: 60]\n";
    std::cout << "  --env KEY=VALUE         Set environment variable for target\n";
    std::cout << "  --args ARG1 ARG2 ...    Command line arguments for target\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  bscanner ./target_app\n";
    std::cout << "  bscanner --env PATH=/usr/bin --args -v --verbose ./target_app\n";
    std::cout << "  bscanner -o xml -t 120 ./target_app\n";
}

void CliParser::print_usage() const {
    std::cout << "Usage: bscanner [OPTIONS] <binary>\n";
    std::cout << "Use -h or --help for more information.\n";
}