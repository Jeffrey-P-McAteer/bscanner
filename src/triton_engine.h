#pragma once
#include "binary_format.h"
#include "io_tracker.h"
#include "libc_hooks.h"
#include <triton/context.hpp>
#include <map>
#include <vector>
#include <string>
#include <memory>

class TritonEngine {
public:
    explicit TritonEngine(BinaryFormat* binary_format);
    TritonEngine(BinaryFormat* binary_format, int verbosity_level, int max_instructions = 10000);
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
    int verbosity_level_;
    int max_instructions_;
    std::unique_ptr<LibcHooks> libc_hooks_;
    
    void setup_architecture();
    void setup_callbacks();
    void memory_callback(triton::Context& ctx, const triton::arch::MemoryAccess& mem);
    void check_syscall(const triton::arch::Instruction& instruction);
    bool is_exit_syscall(const triton::arch::Instruction& instruction);
    void log_instruction(const triton::arch::Instruction& instruction, int verbosity_level);
    void simulate_instruction_effects(const triton::arch::Instruction& instruction, const std::string& disasm);
    void setup_libc_hooks_with_args();
};
