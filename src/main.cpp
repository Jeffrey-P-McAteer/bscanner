#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include "binary_analyzer.h"
#include "cli_parser.h"

int main(int argc, char* argv[]) {
    try {
        CliParser parser;
        auto config = parser.parse(argc, argv);
        
        if (config.help_requested) {
            parser.print_help();
            return 0;
        }
        
        if (config.target_binary.empty()) {
            std::cerr << "Error: No target binary specified\n";
            parser.print_usage();
            return 1;
        }
        
        auto analyzer = std::make_unique<BinaryAnalyzer>(config);
        analyzer->analyze();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}