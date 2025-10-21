#include "libc_hooks.h"
#include <iostream>
#include <cstring>

LibcHooks::LibcHooks(triton::Context& ctx) 
    : triton_ctx_(ctx), main_hooked_(false), main_address_(0), argc_value_(0), argv_address_(0) {
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