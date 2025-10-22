#include "binary_analyzer.h"
#include "elf_format.h"
#include "pe_format.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <chrono>
#include <unistd.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#elif defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#endif

BinaryAnalyzer::BinaryAnalyzer(const AnalysisConfig& config) 
    : config_(config), network_monitoring_active_(false), target_process_id_(0) {
    detect_binary_format();
    setup_triton_engine();
    io_tracker_ = std::make_unique<IOTracker>(config_.verbosity_level);
    setup_network_monitoring();
}

BinaryAnalyzer::~BinaryAnalyzer() {
    stop_network_monitoring();
}

void BinaryAnalyzer::analyze() {
    if (config_.verbosity_level > 0) {
        std::cout << "Starting analysis of: " << config_.target_binary << std::endl;
    }
    
    // Start network monitoring before analysis
    start_network_monitoring();
    
    run_analysis();
    
    // Stop network monitoring after analysis
    stop_network_monitoring();
    
    generate_report();
}

void BinaryAnalyzer::detect_binary_format() {
    std::ifstream file(config_.target_binary, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open binary file: " + config_.target_binary);
    }
    
    char magic[4];
    file.read(magic, 4);
    
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        binary_format_ = std::make_unique<ElfFormat>(config_.target_binary);
        if (config_.verbosity_level > 0) {
            std::cout << "Detected ELF format" << std::endl;
        }
    } else if (magic[0] == 'M' && magic[1] == 'Z') {
        binary_format_ = std::make_unique<PeFormat>(config_.target_binary);
        if (config_.verbosity_level > 0) {
            std::cout << "Detected PE format" << std::endl;
        }
    } else {
        throw std::runtime_error("Unsupported binary format");
    }
}

void BinaryAnalyzer::setup_triton_engine() {
    triton_engine_ = std::make_unique<TritonEngine>(binary_format_.get(), config_.verbosity_level, config_.max_instructions);
}

void BinaryAnalyzer::run_analysis() {
    triton_engine_->load_binary();
    triton_engine_->set_environment(config_.env_vars);
    triton_engine_->set_arguments(config_.cli_args);
    triton_engine_->set_io_tracker(io_tracker_.get());
    
    triton_engine_->execute_with_timeout(config_.timeout_seconds);
}

void BinaryAnalyzer::generate_report() {
    auto input_map = io_tracker_->get_input_mappings();
    auto output_map = io_tracker_->get_output_mappings();
    
    if (config_.output_format == "json") {
        io_tracker_->output_json_report(std::cout);
    } else if (config_.output_format == "xml") {
        io_tracker_->output_xml_report(std::cout);
    } else {
        io_tracker_->output_text_report(std::cout);
    }
}

void BinaryAnalyzer::setup_network_monitoring() {
#ifdef __linux__
    network_monitor_ = std::make_unique<NetworkMonitor>(io_tracker_.get());
#elif defined(_WIN32)
    network_monitor_ = std::make_unique<WindowsNetworkMonitor>();
#endif
}

void BinaryAnalyzer::start_network_monitoring() {
    if (network_monitoring_active_.load()) {
        return; // Already monitoring
    }
    
    if (config_.verbosity_level > 1) {
        std::cout << "[BScanner] Starting network monitoring..." << std::endl;
    }
    
#ifdef __linux__
    // On Linux, we'll spawn the target process and monitor it
    target_process_id_ = fork();
    if (target_process_id_ == 0) {
        // Child process - execute the target binary
        if (config_.verbosity_level > 1) {
            std::cout << "[BScanner] Child process executing target binary" << std::endl;
        }
        
        // Prepare arguments for execv
        std::vector<char*> argv_ptrs;
        argv_ptrs.push_back(const_cast<char*>(config_.target_binary.c_str()));
        for (const auto& arg : config_.cli_args) {
            argv_ptrs.push_back(const_cast<char*>(arg.c_str()));
        }
        argv_ptrs.push_back(nullptr);
        
        // Allow parent to trace us
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            perror("ptrace PTRACE_TRACEME failed");
            exit(1);
        }
        
        // Execute the target binary
        execv(config_.target_binary.c_str(), argv_ptrs.data());
        perror("execv failed");
        exit(1);
    } else if (target_process_id_ > 0) {
        // Parent process - start monitoring
        network_monitoring_active_.store(true);
        network_thread_ = std::thread(&BinaryAnalyzer::network_monitoring_thread, this);
    } else {
        std::cerr << "[BScanner] Failed to fork process for network monitoring" << std::endl;
    }
    
#elif defined(_WIN32)
    // On Windows, we'll spawn the process and monitor it using ETW
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    std::string cmdline = config_.target_binary;
    for (const auto& arg : config_.cli_args) {
        cmdline += " " + arg;
    }
    
    if (CreateProcessA(nullptr, const_cast<char*>(cmdline.c_str()), nullptr, nullptr, 
                      FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        target_process_id_ = pi.dwProcessId;
        
        network_monitoring_active_.store(true);
        
        // Start Windows network monitoring
        network_monitor_->start_monitoring(target_process_id_, 
            [this](const WindowsNetworkMonitor::NetworkEvent& event) {
                on_windows_network_event(event);
            });
        
        // Clean up process handles
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        std::cerr << "[BScanner] Failed to create process for Windows monitoring" << std::endl;
    }
#endif
}

void BinaryAnalyzer::stop_network_monitoring() {
    if (!network_monitoring_active_.load()) {
        return;
    }
    
    if (config_.verbosity_level > 1) {
        std::cout << "[BScanner] Stopping network monitoring..." << std::endl;
    }
    
    network_monitoring_active_.store(false);
    
#ifdef __linux__
    if (network_monitor_) {
        network_monitor_->stop_monitoring();
    }
    
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    
    // Clean up child process if still running
    if (target_process_id_ > 0) {
        kill(target_process_id_, SIGTERM);
        int status;
        waitpid(target_process_id_, &status, 0);
        target_process_id_ = 0;
    }
    
#elif defined(_WIN32)
    if (network_monitor_) {
        network_monitor_->stop_monitoring();
    }
#endif
}

#ifdef __linux__
void BinaryAnalyzer::network_monitoring_thread() {
    if (!network_monitor_ || target_process_id_ <= 0) {
        return;
    }
    
    // Wait for child to start
    int status;
    waitpid(target_process_id_, &status, 0);
    
    if (WIFSTOPPED(status)) {
        // Start network monitoring
        network_monitor_->start_monitoring(target_process_id_);
        
        // Continue the child process
        ptrace(PTRACE_CONT, target_process_id_, nullptr, nullptr);
        
        // Monitor the process
        auto start_time = std::chrono::steady_clock::now();
        auto max_runtime = std::chrono::seconds(config_.timeout_seconds);
        
        while (network_monitoring_active_.load()) {
            int wait_status;
            pid_t result = waitpid(target_process_id_, &wait_status, WNOHANG);
            
            if (result == target_process_id_) {
                // Child has exited
                if (config_.verbosity_level > 1) {
                    if (WIFEXITED(wait_status)) {
                        std::cout << "[BScanner] Target process exited with status " << WEXITSTATUS(wait_status) << std::endl;
                    } else if (WIFSIGNALED(wait_status)) {
                        std::cout << "[BScanner] Target process killed by signal " << WTERMSIG(wait_status) << std::endl;
                    }
                }
                break;
            } else if (result == 0) {
                // Child still running - check timeout
                auto current_time = std::chrono::steady_clock::now();
                if (current_time - start_time > max_runtime) {
                    if (config_.verbosity_level > 1) {
                        std::cout << "[BScanner] Network monitoring timeout reached" << std::endl;
                    }
                    kill(target_process_id_, SIGTERM);
                    waitpid(target_process_id_, &wait_status, 0);
                    break;
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                // Error in waitpid
                break;
            }
        }
        
        network_monitor_->stop_monitoring();
    }
}

#elif defined(_WIN32)
void BinaryAnalyzer::on_windows_network_event(const WindowsNetworkMonitor::NetworkEvent& event) {
    // Convert Windows network event to IOTracker format
    if (event.type == WindowsNetworkMonitor::NetworkEvent::NETWORK_RECV) {
        std::string data(event.data.begin(), event.data.end());
        io_tracker_->track_network_read(data, "socket:" + std::to_string(event.socket_handle));
    } else if (event.type == WindowsNetworkMonitor::NetworkEvent::NETWORK_SEND) {
        std::string data(event.data.begin(), event.data.end());
        io_tracker_->track_network_write(data, "socket:" + std::to_string(event.socket_handle));
    }
    
    if (config_.verbosity_level > 2) {
        std::cout << "[BScanner] Network event: Type=" << event.type 
                  << ", PID=" << event.process_id 
                  << ", Data size=" << event.data_size << std::endl;
    }
}
#endif