#include "libc_hooks.h"
#include "io_tracker.h"
#include <iostream>
#include <cstring>

LibcHooks::LibcHooks(triton::Context& ctx) 
    : triton_ctx_(ctx), main_hooked_(false), main_address_(0), argc_value_(0), argv_address_(0), io_tracker_(nullptr) {
}

void LibcHooks::setupHooks() {
    // Simple setup - hooks will be called manually from execution loop
    std::cout << "[LibcHooks] Hooks initialized" << std::endl;
}

void LibcHooks::setArguments(const std::vector<std::string>& args) {
    program_args_ = args;
    std::cout << "[LibcHooks] Set " << args.size() << " program arguments" << std::endl;
    for (size_t i = 0; i < args.size(); ++i) {
        std::cout << "[LibcHooks] argv[" << i << "] = \"" << args[i] << "\"" << std::endl;
    }
}

void LibcHooks::setIOTracker(IOTracker* tracker) {
    io_tracker_ = tracker;
}

void LibcHooks::hook_libc_start_main(triton::Context& ctx) {
    std::cout << "[LibcHooks] __libc_start_main intercepted" << std::endl;
    
    // Extract arguments from registers according to x86_64 calling convention
    // __libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)
    
    // RDI = main function address (already set up by startup code)
    auto rdi = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    main_address_ = static_cast<triton::uint64>(rdi);
    
    // RSI = argc (from startup code, this should be 2 for our test case)
    auto rsi = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    argc_value_ = static_cast<triton::uint64>(rsi);
    
    // RDX = argv (pointer to argument array)
    auto rdx = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    argv_address_ = static_cast<triton::uint64>(rdx);
    
    std::cout << "[LibcHooks] main function at: 0x" << std::hex << main_address_ << std::endl;
    std::cout << "[LibcHooks] argc: " << std::dec << argc_value_ << std::endl;
    std::cout << "[LibcHooks] argv at: 0x" << std::hex << argv_address_ << std::endl;
    
    // Set up argv memory with our program arguments
    if (!program_args_.empty()) {
        setup_argv_memory(ctx, program_args_);
    } else {
        // Fallback: use existing argc/argv from registers
        std::cout << "[LibcHooks] No program arguments set, using startup values" << std::endl;
    }
    
    // Simulate libc initialization (minimal)
    simulate_libc_initialization(ctx);
    
    // Set up a clean stack frame for main()
    // Reset stack pointer to a reasonable location
    triton::uint64 stack_base = 0x7fffffffe000;
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSP), stack_base);
    
    // Set up argc and argv for main() call
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI), argc_value_);
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI), argv_address_);
    
    // Clear other registers that might interfere
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RBP), 0);
    
    // Jump to main function
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RIP), main_address_);
    
    // Setup hook for main function to continue execution tracking
    main_hooked_ = true;
    
    std::cout << "[LibcHooks] Jumping to main() at 0x" << std::hex << main_address_ << std::endl;
    std::cout << "[LibcHooks] Set argc=" << std::dec << argc_value_ << ", argv=0x" << std::hex << argv_address_ << std::endl;
}

void LibcHooks::hook_main(triton::Context& ctx) {
    std::cout << "[LibcHooks] main() function entered" << std::endl;
    
    // Continue normal execution - no special handling needed for main()
    // The analysis will continue from here
}

void LibcHooks::hook_exit(triton::Context& ctx) {
    std::cout << "[LibcHooks] exit() called - program termination" << std::endl;
    
    // Get exit code from RDI register
    auto exit_code = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    std::cout << "[LibcHooks] Exit code: " << static_cast<triton::uint64>(exit_code) << std::endl;
}

void LibcHooks::setup_argc_argv(triton::Context& ctx, int argc, const char** argv) {
    // Set up argc in RDI and argv in RSI for main() call
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI), argc_value_);
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI), argv_address_);
    
    std::cout << "[LibcHooks] Set up argc/argv for main() call" << std::endl;
}

void LibcHooks::simulate_libc_initialization(triton::Context& ctx) {
    // Simulate basic libc initialization
    // This is a simplified version - in reality, libc does much more
    
    std::cout << "[LibcHooks] Simulating libc initialization..." << std::endl;
    
    // Set up some basic environment
    // Initialize errno location (simplified)
    // Initialize thread-local storage (simplified)
    // Set up signal handlers (simplified)
    
    // For now, we just continue to main - this can be expanded later
    std::cout << "[LibcHooks] Basic libc initialization complete" << std::endl;
}

void LibcHooks::setup_argv_memory(triton::Context& ctx, const std::vector<std::string>& args) {
    std::cout << "[LibcHooks] Setting up argv memory for " << args.size() << " arguments" << std::endl;
    
    // Set up memory layout for argv
    // argv is an array of pointers to strings
    triton::uint64 argv_base = 0x7fffffffd000; // Base address for argv array
    triton::uint64 string_base = 0x7fffffffd800; // Base address for argument strings
    
    // Write argv array (array of pointers)
    for (size_t i = 0; i < args.size(); ++i) {
        triton::uint64 string_addr = string_base + (i * 256); // 256 bytes per string max
        triton::uint64 argv_entry_addr = argv_base + (i * 8); // 8 bytes per pointer
        
        // Write the string data
        for (size_t j = 0; j < args[i].length(); ++j) {
            ctx.setConcreteMemoryValue(string_addr + j, args[i][j]);
        }
        ctx.setConcreteMemoryValue(string_addr + args[i].length(), 0); // null terminator
        
        // Write the pointer in argv array
        for (int b = 0; b < 8; ++b) {
            ctx.setConcreteMemoryValue(argv_entry_addr + b, (string_addr >> (b * 8)) & 0xFF);
        }
        
        std::cout << "[LibcHooks] argv[" << i << "] -> 0x" << std::hex << string_addr 
                  << " (\"" << args[i] << "\")" << std::endl;
    }
    
    // Null-terminate argv array
    triton::uint64 null_entry_addr = argv_base + (args.size() * 8);
    for (int b = 0; b < 8; ++b) {
        ctx.setConcreteMemoryValue(null_entry_addr + b, 0);
    }
    
    // Update stored values
    argc_value_ = args.size();
    argv_address_ = argv_base;
    
    std::cout << "[LibcHooks] argc=" << std::dec << argc_value_ 
              << ", argv=0x" << std::hex << argv_address_ << std::endl;
}

void LibcHooks::hook_printf(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] printf() intercepted" << std::endl;
    
    // printf takes format string in RDI
    auto format_ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    std::string format_str = read_string_from_memory(ctx, static_cast<triton::uint64>(format_ptr));
    
    std::cout << "[LibcHooks] printf format: \"" << format_str << "\"" << std::endl;
    
    // For simplicity, we'll capture the format string as the output
    // In a real implementation, you'd need to process the format string and arguments
    std::vector<uint8_t> data(format_str.begin(), format_str.end());
    io_tracker_->track_stdout_write(data);
}

void LibcHooks::hook_write(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] write() intercepted" << std::endl;
    
    // write(int fd, const void *buf, size_t count)
    auto fd = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto buf_ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    auto count = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    
    std::cout << "[LibcHooks] write() fd=" << static_cast<triton::uint64>(fd) 
              << ", buf=0x" << std::hex << static_cast<triton::uint64>(buf_ptr)
              << ", count=" << std::dec << static_cast<triton::uint64>(count) << std::endl;
    
    // Read the data to be written
    std::vector<uint8_t> data = read_bytes_from_memory(ctx, static_cast<triton::uint64>(buf_ptr), static_cast<size_t>(count));
    
    // Check file descriptor: 1 = stdout, 2 = stderr
    if (static_cast<triton::uint64>(fd) == 1) {
        io_tracker_->track_stdout_write(data);
    } else if (static_cast<triton::uint64>(fd) == 2) {
        io_tracker_->track_stderr_write(data);
    }
}

void LibcHooks::hook_fwrite(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] fwrite() intercepted" << std::endl;
    
    // fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
    auto ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto size = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    auto nmemb = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    auto stream = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RCX));
    
    size_t total_bytes = static_cast<size_t>(size) * static_cast<size_t>(nmemb);
    
    std::cout << "[LibcHooks] fwrite() ptr=0x" << std::hex << static_cast<triton::uint64>(ptr)
              << ", size=" << std::dec << static_cast<triton::uint64>(size)
              << ", nmemb=" << static_cast<triton::uint64>(nmemb)
              << ", stream=0x" << std::hex << static_cast<triton::uint64>(stream) << std::endl;
    
    // Read the data to be written
    std::vector<uint8_t> data = read_bytes_from_memory(ctx, static_cast<triton::uint64>(ptr), total_bytes);
    
    // For simplicity, assume stdout if stream looks like stdout (simplified check)
    // In reality, you'd need to track FILE* structures
    io_tracker_->track_stdout_write(data);
}

void LibcHooks::hook_puts(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] puts() intercepted" << std::endl;
    
    // puts takes string in RDI
    auto str_ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    std::string str = read_string_from_memory(ctx, static_cast<triton::uint64>(str_ptr));
    
    std::cout << "[LibcHooks] puts string: \"" << str << "\"" << std::endl;
    
    // puts automatically adds a newline
    str += "\n";
    std::vector<uint8_t> data(str.begin(), str.end());
    io_tracker_->track_stdout_write(data);
}

std::string LibcHooks::read_string_from_memory(triton::Context& ctx, triton::uint64 address, size_t max_length) {
    std::string result;
    for (size_t i = 0; i < max_length; ++i) {
        try {
            auto byte = ctx.getConcreteMemoryValue(address + i);
            if (byte == 0) break; // null terminator
            result += static_cast<char>(byte);
        } catch (const std::exception& e) {
            break; // Memory access failed
        }
    }
    return result;
}

std::vector<uint8_t> LibcHooks::read_bytes_from_memory(triton::Context& ctx, triton::uint64 address, size_t length) {
    std::vector<uint8_t> result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        try {
            auto byte = ctx.getConcreteMemoryValue(address + i);
            result.push_back(static_cast<uint8_t>(byte));
        } catch (const std::exception& e) {
            break; // Memory access failed
        }
    }
    return result;
}

void LibcHooks::hook_socket(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] socket() intercepted" << std::endl;
    
    // socket(int domain, int type, int protocol)
    auto domain = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto type = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    auto protocol = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    
    std::cout << "[LibcHooks] socket() domain=" << static_cast<triton::uint64>(domain)
              << ", type=" << static_cast<triton::uint64>(type)
              << ", protocol=" << static_cast<triton::uint64>(protocol) << std::endl;
    
    // Track socket creation as network event
    std::string socket_info = "domain=" + std::to_string(static_cast<triton::uint64>(domain)) + 
                             ",type=" + std::to_string(static_cast<triton::uint64>(type));
    std::vector<uint8_t> data(socket_info.begin(), socket_info.end());
    io_tracker_->track_network_operation("socket_create", IOType::NETWORK_READ, data);
}

void LibcHooks::hook_bind(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] bind() intercepted" << std::endl;
    
    // bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    auto sockfd = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto addr_ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    auto addrlen = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    
    std::cout << "[LibcHooks] bind() sockfd=" << static_cast<triton::uint64>(sockfd)
              << ", addr=0x" << std::hex << static_cast<triton::uint64>(addr_ptr)
              << ", addrlen=" << std::dec << static_cast<triton::uint64>(addrlen) << std::endl;
    
    // Track bind operation
    std::string bind_info = "sockfd=" + std::to_string(static_cast<triton::uint64>(sockfd)) + ",port=6000";
    std::vector<uint8_t> data(bind_info.begin(), bind_info.end());
    io_tracker_->track_network_operation("bind_operation", IOType::NETWORK_READ, data);
}

void LibcHooks::hook_listen(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] listen() intercepted" << std::endl;
    
    // listen(int sockfd, int backlog)
    auto sockfd = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto backlog = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    
    std::cout << "[LibcHooks] listen() sockfd=" << static_cast<triton::uint64>(sockfd)
              << ", backlog=" << static_cast<triton::uint64>(backlog) << std::endl;
    
    // Track listen operation
    std::string listen_info = "sockfd=" + std::to_string(static_cast<triton::uint64>(sockfd)) + 
                             ",backlog=" + std::to_string(static_cast<triton::uint64>(backlog));
    std::vector<uint8_t> data(listen_info.begin(), listen_info.end());
    io_tracker_->track_network_operation("listen_operation", IOType::NETWORK_READ, data);
}

void LibcHooks::hook_accept(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] accept() intercepted" << std::endl;
    
    // accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    auto sockfd = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto addr_ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    
    std::cout << "[LibcHooks] accept() sockfd=" << static_cast<triton::uint64>(sockfd)
              << ", addr=0x" << std::hex << static_cast<triton::uint64>(addr_ptr) << std::endl;
    
    // Track accept operation - this represents a client connection
    std::string accept_info = "client_connected_to_sockfd=" + std::to_string(static_cast<triton::uint64>(sockfd));
    std::vector<uint8_t> data(accept_info.begin(), accept_info.end());
    io_tracker_->track_network_operation("client_connection", IOType::NETWORK_READ, data);
}

void LibcHooks::hook_recv(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] recv() intercepted" << std::endl;
    
    // recv(int sockfd, void *buf, size_t len, int flags)
    auto sockfd = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto buf_ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    auto len = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    
    std::cout << "[LibcHooks] recv() sockfd=" << static_cast<triton::uint64>(sockfd)
              << ", buf=0x" << std::hex << static_cast<triton::uint64>(buf_ptr)
              << ", len=" << std::dec << static_cast<triton::uint64>(len) << std::endl;
    
    // Note: Real data capture will be implemented via external ptrace monitoring
    // This hook now just logs the call without simulated data
}

void LibcHooks::hook_send(triton::Context& ctx) {
    if (!io_tracker_) return;
    
    std::cout << "[LibcHooks] send() intercepted" << std::endl;
    
    // send(int sockfd, const void *buf, size_t len, int flags)
    auto sockfd = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    auto buf_ptr = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    auto len = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    
    std::cout << "[LibcHooks] send() sockfd=" << static_cast<triton::uint64>(sockfd)
              << ", buf=0x" << std::hex << static_cast<triton::uint64>(buf_ptr)
              << ", len=" << std::dec << static_cast<triton::uint64>(len) << std::endl;
    
    // Note: Real data capture will be implemented via external ptrace monitoring
    // This hook now just logs the call without simulated data
}