#pragma once
#include "cli_parser.h"
#include "binary_format.h"
#include "triton_engine.h"
#include "io_tracker.h"
#ifdef __linux__
#include "network_monitor.h"
#endif
#include <memory>

class BinaryAnalyzer {
public:
    explicit BinaryAnalyzer(const AnalysisConfig& config);
    ~BinaryAnalyzer();
    
    void analyze();

private:
    AnalysisConfig config_;
    std::unique_ptr<BinaryFormat> binary_format_;
    std::unique_ptr<TritonEngine> triton_engine_;
    std::unique_ptr<IOTracker> io_tracker_;
#ifdef __linux__
    std::unique_ptr<NetworkMonitor> network_monitor_;
#endif
    
    void detect_binary_format();
    void setup_triton_engine();
    void run_analysis();
    void generate_report();
};