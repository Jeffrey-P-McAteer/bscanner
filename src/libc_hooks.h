#pragma once

#include <triton/context.hpp>
#include <string>
#include <vector>

class LibcHooks {
public:
    explicit LibcHooks(triton::Context& ctx);
    
    // Setup hooks for libc functions
    void setupHooks();
    void setArguments(const std::vector<std::string>& args);
    
    // Hook implementations
    void hook_libc_start_main(triton::Context& ctx);
    void hook_main(triton::Context& ctx);
    void hook_exit(triton::Context& ctx);
    
private:
    triton::Context& triton_ctx_;
    bool main_hooked_;
    triton::uint64 main_address_;
    triton::uint64 argc_value_;
    triton::uint64 argv_address_;
    std::vector<std::string> program_args_;
    
    // Helper methods
    void setup_argc_argv(triton::Context& ctx, int argc, const char** argv);
    void simulate_libc_initialization(triton::Context& ctx);
    void setup_argv_memory(triton::Context& ctx, const std::vector<std::string>& args);
};