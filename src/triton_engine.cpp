#include "triton_engine.h"
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <chrono>
#include <thread>

TritonEngine::TritonEngine(BinaryFormat* binary_format) 
    : binary_format_(binary_format), io_tracker_(nullptr) {
    setup_architecture();
    setup_callbacks();
}

TritonEngine::~TritonEngine() = default;

void TritonEngine::setup_architecture() {
    if (binary_format_->is_64bit()) {
        api_.setArchitecture(triton::arch::ARCH_X86_64);
    } else {
        api_.setArchitecture(triton::arch::ARCH_X86);
    }
    
    api_.setMode(triton::modes::ALIGNED_MEMORY, true);
    api_.setMode(triton::modes::AST_OPTIMIZATIONS, true);
}

void TritonEngine::setup_callbacks() {
    api_.addCallback(triton::callbacks::GET_CONCRETE_MEMORY_VALUE, 
        [this](triton::API& api, const triton::MemoryAccess& mem) {
            memory_callback(api, mem);
        });
}

void TritonEngine::load_binary() {
    std::ifstream file(binary_format_->get_path(), std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open binary for loading");
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> binary_data(size);
    file.read(reinterpret_cast<char*>(binary_data.data()), size);
    
    uint64_t base_addr = binary_format_->get_base_address();
    api_.setConcreteMemoryArea(base_addr, binary_data);
    
    if (binary_format_->is_64bit()) {
        api_.setConcreteRegisterValue(api_.getRegister(triton::arch::x86::ID_REG_X86_64_RIP), 
                                      binary_format_->get_entry_point());
        api_.setConcreteRegisterValue(api_.getRegister(triton::arch::x86::ID_REG_X86_64_RSP), 
                                      0x7fffffffe000ULL);
    } else {
        api_.setConcreteRegisterValue(api_.getRegister(triton::arch::x86::ID_REG_X86_EIP), 
                                      static_cast<uint32_t>(binary_format_->get_entry_point()));
        api_.setConcreteRegisterValue(api_.getRegister(triton::arch::x86::ID_REG_X86_ESP), 
                                      0xbffff000U);
    }
}

void TritonEngine::set_environment(const std::map<std::string, std::string>& env_vars) {
    env_vars_ = env_vars;
}

void TritonEngine::set_arguments(const std::vector<std::string>& args) {
    args_ = args;
}

void TritonEngine::set_io_tracker(IOTracker* tracker) {
    io_tracker_ = tracker;
}

void TritonEngine::execute_with_timeout(int timeout_seconds) {
    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds);
    
    try {
        while (true) {
            auto current_time = std::chrono::steady_clock::now();
            if (current_time - start_time > timeout) {
                std::cout << "Execution timeout reached" << std::endl;
                break;
            }
            
            triton::uint64 pc;
            if (binary_format_->is_64bit()) {
                pc = api_.getConcreteRegisterValue(api_.getRegister(triton::arch::x86::ID_REG_X86_64_RIP)).convert_to<triton::uint64>();
            } else {
                pc = api_.getConcreteRegisterValue(api_.getRegister(triton::arch::x86::ID_REG_X86_EIP)).convert_to<triton::uint64>();
            }
            
            auto instruction = triton::Instruction();
            instruction.setAddress(pc);
            
            triton::uint8 opcodes[16];
            api_.getConcreteMemoryArea(pc, opcodes, 16);
            instruction.setOpcodes(opcodes, 16);
            
            if (!api_.processing(instruction)) {
                std::cout << "Execution finished or invalid instruction" << std::endl;
                break;
            }
            
            std::this_thread::sleep_for(std::chrono::microseconds(1));
        }
    } catch (const std::exception& e) {
        std::cerr << "Execution error: " << e.what() << std::endl;
    }
}

void TritonEngine::memory_callback(triton::API& api, const triton::MemoryAccess& mem) {
    if (io_tracker_) {
        io_tracker_->track_memory_access(mem.getAddress(), mem.getSize(), mem.getType());
    }
}

void TritonEngine::syscall_callback(triton::API& api, const triton::syscalls::SyscallEntry& syscall) {
    if (io_tracker_) {
        io_tracker_->track_syscall(syscall.getNumber(), syscall.getName());
    }
}