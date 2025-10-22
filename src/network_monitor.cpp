#include "network_monitor.h"
#include "io_tracker.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <thread>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <signal.h>

NetworkMonitor::NetworkMonitor(IOTracker* tracker) 
    : io_tracker_(tracker), target_pid_(0), monitoring_active_(false), monitor_thread_ptr_(nullptr) {
}

NetworkMonitor::~NetworkMonitor() {
    stop_monitoring();
}

bool NetworkMonitor::start_monitoring(pid_t target_pid) {
    if (monitoring_active_) {
        std::cerr << "[NetworkMonitor] Already monitoring" << std::endl;
        return false;
    }
    
    target_pid_ = target_pid;
    monitoring_active_ = true;
    
    // Start monitoring thread
    monitor_thread_ptr_ = new std::thread(&NetworkMonitor::monitor_thread, this);
    
    std::cout << "[NetworkMonitor] Started monitoring PID " << target_pid << std::endl;
    return true;
}

void NetworkMonitor::stop_monitoring() {
    if (!monitoring_active_) return;
    
    monitoring_active_ = false;
    
    if (monitor_thread_ptr_) {
        if (monitor_thread_ptr_->joinable()) {
            monitor_thread_ptr_->join();
        }
        delete monitor_thread_ptr_;
        monitor_thread_ptr_ = nullptr;
    }
    
    std::cout << "[NetworkMonitor] Stopped monitoring" << std::endl;
}

void NetworkMonitor::monitor_thread() {
    if (ptrace(PTRACE_ATTACH, target_pid_, nullptr, nullptr) == -1) {
        perror("[NetworkMonitor] ptrace PTRACE_ATTACH failed");
        return;
    }
    
    // Wait for the process to stop
    int status;
    waitpid(target_pid_, &status, 0);
    
    // Set options to trace syscalls
    if (ptrace(PTRACE_SETOPTIONS, target_pid_, nullptr, PTRACE_O_TRACESYSGOOD) == -1) {
        perror("[NetworkMonitor] ptrace PTRACE_SETOPTIONS failed");
        ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr);
        return;
    }
    
    std::cout << "[NetworkMonitor] Attached to process " << target_pid_ << std::endl;
    
    bool in_syscall = false;
    
    while (monitoring_active_) {
        // Continue execution until next syscall
        if (ptrace(PTRACE_SYSCALL, target_pid_, nullptr, nullptr) == -1) {
            if (monitoring_active_) {
                perror("[NetworkMonitor] ptrace PTRACE_SYSCALL failed");
            }
            break;
        }
        
        // Wait for syscall
        if (waitpid(target_pid_, &status, 0) == -1) {
            if (monitoring_active_) {
                perror("[NetworkMonitor] waitpid failed");
            }
            break;
        }
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            std::cout << "[NetworkMonitor] Target process exited" << std::endl;
            break;
        }
        
        if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
            // Syscall stop
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, target_pid_, nullptr, &regs) == -1) {
                perror("[NetworkMonitor] ptrace PTRACE_GETREGS failed");
                continue;
            }
            
            if (!in_syscall) {
                // Syscall entry
                current_syscall_.syscall_num = regs.orig_rax;
                current_syscall_.arg1 = regs.rdi;
                current_syscall_.arg2 = regs.rsi;
                current_syscall_.arg3 = regs.rdx;
                current_syscall_.arg4 = regs.r10;
                
                handle_syscall_entry(target_pid_, current_syscall_.syscall_num);
                in_syscall = true;
            } else {
                // Syscall exit
                long return_value = regs.rax;
                handle_syscall_exit(target_pid_, current_syscall_.syscall_num, return_value);
                in_syscall = false;
            }
        }
    }
    
    // Detach from process
    ptrace(PTRACE_DETACH, target_pid_, nullptr, nullptr);
    std::cout << "[NetworkMonitor] Detached from process " << target_pid_ << std::endl;
}

void NetworkMonitor::handle_syscall_entry(pid_t pid, long syscall_num) {
    switch (syscall_num) {
        case SYS_socket:
            std::cout << "[NetworkMonitor] socket() entry - domain=" << current_syscall_.arg1 
                      << ", type=" << current_syscall_.arg2 << ", protocol=" << current_syscall_.arg3 << std::endl;
            break;
        case SYS_bind:
            std::cout << "[NetworkMonitor] bind() entry - sockfd=" << current_syscall_.arg1 << std::endl;
            break;
        case SYS_listen:
            std::cout << "[NetworkMonitor] listen() entry - sockfd=" << current_syscall_.arg1 
                      << ", backlog=" << current_syscall_.arg2 << std::endl;
            break;
        case SYS_accept:
        case SYS_accept4:
            std::cout << "[NetworkMonitor] accept() entry - sockfd=" << current_syscall_.arg1 << std::endl;
            break;
        case SYS_recvfrom:
            // SYS_recvfrom is already 45 on x86_64
            std::cout << "[NetworkMonitor] recv() entry - sockfd=" << current_syscall_.arg1 
                      << ", buf=0x" << std::hex << current_syscall_.arg2 
                      << ", len=" << std::dec << current_syscall_.arg3 << std::endl;
            break;
        case SYS_sendto:
            // SYS_sendto is already 44 on x86_64
            std::cout << "[NetworkMonitor] send() entry - sockfd=" << current_syscall_.arg1 
                      << ", buf=0x" << std::hex << current_syscall_.arg2 
                      << ", len=" << std::dec << current_syscall_.arg3 << std::endl;
            handle_send_syscall(pid);
            break;
    }
}

void NetworkMonitor::handle_syscall_exit(pid_t pid, long syscall_num, long return_value) {
    switch (syscall_num) {
        case SYS_socket:
            if (return_value >= 0) {
                std::cout << "[NetworkMonitor] socket() exit - returned fd=" << return_value << std::endl;
                handle_socket_syscall(pid, return_value);
            }
            break;
        case SYS_accept:
        case SYS_accept4:
            if (return_value >= 0) {
                std::cout << "[NetworkMonitor] accept() exit - returned fd=" << return_value << std::endl;
                if (io_tracker_) {
                    std::string connection_info = "client_connected_fd=" + std::to_string(return_value);
                    std::vector<uint8_t> data(connection_info.begin(), connection_info.end());
                    io_tracker_->track_network_operation("accept:" + std::to_string(return_value), IOType::NETWORK_READ, data);
                }
            }
            break;
        case SYS_recvfrom:
            // SYS_recvfrom is already 45 on x86_64
            if (return_value > 0) {
                std::cout << "[NetworkMonitor] recv() exit - received " << return_value << " bytes" << std::endl;
                handle_recv_syscall(pid, return_value);
            }
            break;
        case SYS_sendto:
            // SYS_sendto is already 44 on x86_64
            if (return_value > 0) {
                std::cout << "[NetworkMonitor] send() exit - sent " << return_value << " bytes" << std::endl;
            }
            break;
    }
}

void NetworkMonitor::handle_recv_syscall(pid_t pid, long return_value) {
    if (!io_tracker_ || return_value <= 0) return;
    
    // Read the actual data that was received
    uint64_t buf_addr = current_syscall_.arg2;
    size_t bytes_received = static_cast<size_t>(return_value);
    
    std::vector<uint8_t> data = read_process_memory(pid, buf_addr, bytes_received);
    
    if (!data.empty()) {
        std::string endpoint = "socket:" + std::to_string(current_syscall_.arg1);
        io_tracker_->track_network_operation(endpoint, IOType::NETWORK_READ, data);
        
        std::cout << "[NetworkMonitor] Captured " << data.size() << " bytes from recv()" << std::endl;
        // Print first 32 bytes as hex for debugging
        std::cout << "[NetworkMonitor] Data: ";
        for (size_t i = 0; i < std::min(data.size(), static_cast<size_t>(32)); ++i) {
            printf("%02x ", data[i]);
        }
        std::cout << std::endl;
    }
}

void NetworkMonitor::handle_send_syscall(pid_t pid) {
    if (!io_tracker_) return;
    
    // Read the data being sent
    uint64_t buf_addr = current_syscall_.arg2;
    size_t bytes_to_send = static_cast<size_t>(current_syscall_.arg3);
    
    std::vector<uint8_t> data = read_process_memory(pid, buf_addr, bytes_to_send);
    
    if (!data.empty()) {
        std::string endpoint = "socket:" + std::to_string(current_syscall_.arg1);
        io_tracker_->track_network_operation(endpoint, IOType::NETWORK_WRITE, data);
        
        std::cout << "[NetworkMonitor] Captured " << data.size() << " bytes from send()" << std::endl;
        // Print first 32 bytes as hex for debugging
        std::cout << "[NetworkMonitor] Data: ";
        for (size_t i = 0; i < std::min(data.size(), static_cast<size_t>(32)); ++i) {
            printf("%02x ", data[i]);
        }
        std::cout << std::endl;
    }
}

void NetworkMonitor::handle_socket_syscall(pid_t pid, long return_value) {
    if (!io_tracker_) return;
    
    std::string socket_info = "fd=" + std::to_string(return_value) + 
                              ",domain=" + std::to_string(current_syscall_.arg1) + 
                              ",type=" + std::to_string(current_syscall_.arg2);
    std::vector<uint8_t> data(socket_info.begin(), socket_info.end());
    io_tracker_->track_network_operation("socket_create", IOType::NETWORK_READ, data);
}

std::vector<uint8_t> NetworkMonitor::read_process_memory(pid_t pid, uint64_t address, size_t length) {
    std::vector<uint8_t> result;
    result.reserve(length);
    
    // Use process_vm_readv for efficient memory reading
    struct iovec local_iov;
    struct iovec remote_iov;
    
    std::vector<uint8_t> buffer(length);
    local_iov.iov_base = buffer.data();
    local_iov.iov_len = length;
    
    remote_iov.iov_base = reinterpret_cast<void*>(address);
    remote_iov.iov_len = length;
    
    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    
    if (bytes_read > 0) {
        result.assign(buffer.begin(), buffer.begin() + bytes_read);
    }
    
    return result;
}