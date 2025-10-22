#pragma once
#include "cli_parser.h"
#include "binary_format.h"
#include "triton_engine.h"
#include "io_tracker.h"
#ifdef __linux__
#include "network_monitor.h"
#elif defined(_WIN32)
#include "network_monitor_windows.h"
#endif
#include <memory>
#include <thread>
#include <atomic>

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
#elif defined(_WIN32)
    std::unique_ptr<WindowsNetworkMonitor> network_monitor_;
#endif
    
    // Network monitoring state
    std::atomic<bool> network_monitoring_active_;
    std::thread network_thread_;
    pid_t target_process_id_;
    
    void detect_binary_format();
    void setup_triton_engine();
    void setup_network_monitoring();
    void start_network_monitoring();
    void stop_network_monitoring();
    void run_analysis();
    void generate_report();
    
#ifdef __linux__
    void network_monitoring_thread();
#elif defined(_WIN32)
    void on_windows_network_event(const WindowsNetworkMonitor::NetworkEvent& event);
#endif
};