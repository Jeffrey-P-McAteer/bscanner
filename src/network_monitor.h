#pragma once

#include <sys/types.h>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <thread>

class IOTracker;

struct NetworkEvent {
    enum Type {
        SOCKET_CREATE,
        SOCKET_BIND, 
        SOCKET_LISTEN,
        SOCKET_ACCEPT,
        NETWORK_RECV,
        NETWORK_SEND
    };
    
    Type type;
    int sockfd;
    std::string endpoint;
    std::vector<uint8_t> data;
    uint64_t timestamp;
};

class NetworkMonitor {
public:
    explicit NetworkMonitor(IOTracker* tracker);
    ~NetworkMonitor();
    
    // Start monitoring a process
    bool start_monitoring(pid_t target_pid);
    
    // Stop monitoring
    void stop_monitoring();
    
    // Check if monitoring is active
    bool is_monitoring() const { return monitoring_active_; }
    
private:
    IOTracker* io_tracker_;
    pid_t target_pid_;
    bool monitoring_active_;
    
    // Ptrace monitoring thread
    void monitor_thread();
    std::thread* monitor_thread_ptr_;
    
    // Syscall handling
    void handle_syscall_entry(pid_t pid, long syscall_num);
    void handle_syscall_exit(pid_t pid, long syscall_num, long return_value);
    
    // Network syscall handlers
    void handle_recv_syscall(pid_t pid, long return_value);
    void handle_send_syscall(pid_t pid);
    void handle_socket_syscall(pid_t pid, long return_value);
    
    // Memory reading utilities
    std::vector<uint8_t> read_process_memory(pid_t pid, uint64_t address, size_t length);
    long get_register_value(pid_t pid, int reg);
    
    // Syscall state tracking
    struct SyscallState {
        long syscall_num;
        uint64_t arg1, arg2, arg3, arg4;
    };
    SyscallState current_syscall_;
};