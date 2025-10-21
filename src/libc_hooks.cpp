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

void LibcHooks::hook_libc_start_main(triton::Context& ctx) {
    std::cout << "[LibcHooks] __libc_start_main called" << std::endl;
    
    // Extract arguments from registers according to x86_64 calling convention
    // __libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)
    
    // RDI = main function address
    auto rdi = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDI));
    main_address_ = static_cast<triton::uint64>(rdi);
    
    // RSI = argc
    auto rsi = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RSI));
    argc_value_ = static_cast<triton::uint64>(rsi);
    
    // RDX = argv
    auto rdx = ctx.getConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RDX));
    argv_address_ = static_cast<triton::uint64>(rdx);
    
    std::cout << "[LibcHooks] main function at: 0x" << std::hex << main_address_ << std::endl;
    std::cout << "[LibcHooks] argc: " << std::dec << argc_value_ << std::endl;
    std::cout << "[LibcHooks] argv at: 0x" << std::hex << argv_address_ << std::endl;
    
    // Simulate libc initialization
    simulate_libc_initialization(ctx);
    
    // Set up stack and registers for main() call
    setup_argc_argv(ctx, static_cast<int>(argc_value_), nullptr);
    
    // Jump to main function
    ctx.setConcreteRegisterValue(ctx.getRegister(triton::arch::ID_REG_X86_RIP), main_address_);
    
    // Setup hook for main function to continue execution tracking
    main_hooked_ = true;
    
    std::cout << "[LibcHooks] Jumping to main() at 0x" << std::hex << main_address_ << std::endl;
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