#pragma once

#include <triton/context.hpp>
#include <string>
#include <vector>

class IOTracker;

class LibcHooks {
public:
    explicit LibcHooks(triton::Context& ctx);
    
    // Setup hooks for libc functions
    void setupHooks();
    void setArguments(const std::vector<std::string>& args);
    void setIOTracker(IOTracker* tracker);
    
    // Hook implementations
    void hook_libc_start_main(triton::Context& ctx);
    void hook_main(triton::Context& ctx);
    void hook_exit(triton::Context& ctx);
    void hook_printf(triton::Context& ctx);
    void hook_write(triton::Context& ctx);
    void hook_fwrite(triton::Context& ctx);
    void hook_puts(triton::Context& ctx);
    void hook_socket(triton::Context& ctx);
    void hook_bind(triton::Context& ctx);
    void hook_listen(triton::Context& ctx);
    void hook_accept(triton::Context& ctx);
    void hook_recv(triton::Context& ctx);
    void hook_send(triton::Context& ctx);
    
private:
    triton::Context& triton_ctx_;
    bool main_hooked_;
    triton::uint64 main_address_;
    triton::uint64 argc_value_;
    triton::uint64 argv_address_;
    std::vector<std::string> program_args_;
    IOTracker* io_tracker_;
    
    // Helper methods
    void setup_argc_argv(triton::Context& ctx, int argc, const char** argv);
    void simulate_libc_initialization(triton::Context& ctx);
    void setup_argv_memory(triton::Context& ctx, const std::vector<std::string>& args);
    std::string read_string_from_memory(triton::Context& ctx, triton::uint64 address, size_t max_length = 1024);
    std::vector<uint8_t> read_bytes_from_memory(triton::Context& ctx, triton::uint64 address, size_t length);
};