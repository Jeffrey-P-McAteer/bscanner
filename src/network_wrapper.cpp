#ifdef _WIN32
#include "network_monitor_windows.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#else
#include "network_monitor.h"
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#endif

#include "io_tracker.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <thread>
#include <chrono>

// This is a standalone network monitoring wrapper
// Usage: ./network_wrapper <target_binary> [args...]
// It monitors the target binary's network activity using platform-specific methods

#ifdef _WIN32
int windows_main(int argc, char* argv[]) {
    // Create IOTracker for collecting network events
    IOTracker io_tracker(3); // verbose level 3
    
    // Create Windows NetworkWrapper
    WindowsNetworkWrapper network_wrapper;
    
    std::cout << "[NetworkWrapper] Starting Windows target: " << argv[1] << std::endl;
    
    // Monitor the process
    if (!network_wrapper.monitor_process(argv[1])) {
        std::cerr << "[NetworkWrapper] Failed to start monitoring" << std::endl;
        return 1;
    }
    
    std::cout << "[NetworkWrapper] Process running... waiting for network activity" << std::endl;
    
    // Let the process run for a while to handle network connections
    auto start_time = std::chrono::steady_clock::now();
    auto max_runtime = std::chrono::seconds(30); // 30 second timeout
    
    std::this_thread::sleep_for(max_runtime);
    
    // Stop monitoring
    network_wrapper.stop_monitoring();
    
    // Convert Windows events to IOTracker format
    auto windows_events = network_wrapper.get_network_events();
    for (const auto& event : windows_events) {
        if (event.type == WindowsNetworkMonitor::NetworkEvent::NETWORK_RECV) {
            io_tracker.track_network_read(event.data, "socket:" + std::to_string(event.socket_handle));
        } else if (event.type == WindowsNetworkMonitor::NetworkEvent::NETWORK_SEND) {
            io_tracker.track_network_write(event.data, "socket:" + std::to_string(event.socket_handle));
        }
    }
    
    // Generate report
    std::cout << "\n[NetworkWrapper] ========== NETWORK ANALYSIS REPORT ==========" << std::endl;
    io_tracker.output_text_report(std::cout);
    
    // Also output JSON report
    std::cout << "\n[NetworkWrapper] ========== JSON REPORT ==========" << std::endl;
    io_tracker.output_json_report(std::cout);
    
    return 0;
}
#endif

#ifdef __linux__
int linux_main(int argc, char* argv[]) {
    // Create IOTracker for collecting network events
    IOTracker io_tracker(3); // verbose level 3
    
    // Create NetworkMonitor
    NetworkMonitor network_monitor(&io_tracker);
    
    std::cout << "[NetworkWrapper] Starting Linux target: " << argv[1] << std::endl;
    
    // Fork to create child process
    pid_t child_pid = fork();
    
    if (child_pid == -1) {
        perror("fork failed");
        return 1;
    }
    
    if (child_pid == 0) {
        // Child process - run the target binary
        std::cout << "[NetworkWrapper] Child process starting target binary" << std::endl;
        
        // Allow parent to trace us
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            perror("ptrace PTRACE_TRACEME failed");
            return 1;
        }
        
        // Execute the target binary
        execv(argv[1], &argv[1]);
        perror("execv failed");
        return 1;
    } else {
        // Parent process - monitor the child
        std::cout << "[NetworkWrapper] Parent process monitoring child PID " << child_pid << std::endl;
        
        // Wait for child to start
        int status;
        waitpid(child_pid, &status, 0);
        
        if (WIFSTOPPED(status)) {
            // Start network monitoring
            network_monitor.start_monitoring(child_pid);
            
            // Continue the child process
            ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
            
            // Let the process run for a while to handle network connections
            std::cout << "[NetworkWrapper] Process running... waiting for network activity" << std::endl;
            
            // Wait for child to exit or run for a maximum time
            auto start_time = std::chrono::steady_clock::now();
            auto max_runtime = std::chrono::seconds(30); // 30 second timeout
            
            while (true) {
                int wait_status;
                pid_t result = waitpid(child_pid, &wait_status, WNOHANG);
                
                if (result == child_pid) {
                    // Child has exited
                    if (WIFEXITED(wait_status)) {
                        std::cout << "[NetworkWrapper] Child process exited with status " << WEXITSTATUS(wait_status) << std::endl;
                    } else if (WIFSIGNALED(wait_status)) {
                        std::cout << "[NetworkWrapper] Child process killed by signal " << WTERMSIG(wait_status) << std::endl;
                    }
                    break;
                } else if (result == 0) {
                    // Child still running
                    auto current_time = std::chrono::steady_clock::now();
                    if (current_time - start_time > max_runtime) {
                        std::cout << "[NetworkWrapper] Timeout reached, terminating child" << std::endl;
                        kill(child_pid, SIGTERM);
                        waitpid(child_pid, &wait_status, 0);
                        break;
                    }
                    
                    // Sleep briefly before checking again
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                } else {
                    perror("waitpid failed");
                    break;
                }
            }
            
            // Stop monitoring
            network_monitor.stop_monitoring();
            
            // Generate report
            std::cout << "\n[NetworkWrapper] ========== NETWORK ANALYSIS REPORT ==========" << std::endl;
            io_tracker.output_text_report(std::cout);
            
            // Also output JSON report
            std::cout << "\n[NetworkWrapper] ========== JSON REPORT ==========" << std::endl;
            io_tracker.output_json_report(std::cout);
            
        } else {
            std::cerr << "[NetworkWrapper] Failed to start child process" << std::endl;
            return 1;
        }
    }
    
    return 0;
}
#endif

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_binary> [args...]" << std::endl;
        return 1;
    }
    
#ifdef _WIN32
    return windows_main(argc, argv);
#elif defined(__linux__)
    return linux_main(argc, argv);
#else
    std::cerr << "Unsupported platform" << std::endl;
    return 1;
#endif
}