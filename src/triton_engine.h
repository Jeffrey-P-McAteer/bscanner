#pragma once
#include "binary_format.h"
#include "io_tracker.h"
#include <triton/context.hpp>
#include <map>
#include <vector>
#include <string>

class TritonEngine {
public:
    explicit TritonEngine(BinaryFormat* binary_format);
    ~TritonEngine();
    
    void load_binary();
    void set_environment(const std::map<std::string, std::string>& env_vars);
    void set_arguments(const std::vector<std::string>& args);
    void set_io_tracker(IOTracker* tracker);
    void execute_with_timeout(int timeout_seconds);

private:
    BinaryFormat* binary_format_;
    IOTracker* io_tracker_;
    triton::Context ctx_;
    std::map<std::string, std::string> env_vars_;
    std::vector<std::string> args_;
    
    void setup_architecture();
    void setup_callbacks();
    void memory_callback(triton::Context& ctx, const triton::arch::MemoryAccess& mem);
    void check_syscall(const triton::arch::Instruction& instruction);
};
