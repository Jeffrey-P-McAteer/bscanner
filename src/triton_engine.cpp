#include "triton_engine.h"
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <chrono>
#include <thread>
#include <iomanip>

TritonEngine::TritonEngine(BinaryFormat* binary_format) 
    : binary_format_(binary_format), io_tracker_(nullptr), verbosity_level_(0) {
    setup_architecture();
    setup_callbacks();
}

TritonEngine::TritonEngine(BinaryFormat* binary_format, int verbosity_level) 
    : binary_format_(binary_format), io_tracker_(nullptr), verbosity_level_(verbosity_level) {
    setup_architecture();
    setup_callbacks();
}

TritonEngine::~TritonEngine() = default;

void TritonEngine::setup_architecture() {
    if (binary_format_->is_64bit()) {
        ctx_.setArchitecture(triton::arch::ARCH_X86_64);
    } else {
        ctx_.setArchitecture(triton::arch::ARCH_X86);
    }
    
    ctx_.setMode(triton::modes::ALIGNED_MEMORY, true);
    ctx_.setMode(triton::modes::AST_OPTIMIZATIONS, true);
}

void TritonEngine::setup_callbacks() {
    ctx_.addCallback(triton::callbacks::GET_CONCRETE_MEMORY_VALUE, 
        triton::ComparableFunctor<void(triton::Context&, const triton::arch::MemoryAccess&)>(
            std::function<void(triton::Context&, const triton::arch::MemoryAccess&)>(
                [this](triton::Context& ctx, const triton::arch::MemoryAccess& mem) {
                    memory_callback(ctx, mem);
                }),
            this));
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
    uint64_t entry_point = binary_format_->get_entry_point();
    
    if (verbosity_level_ > 0) {
        std::cerr << "[LOAD] Binary size: " << size << " bytes" << std::endl;
        std::cerr << "[LOAD] Base address: 0x" << std::hex << base_addr << std::endl;
        std::cerr << "[LOAD] Entry point: 0x" << std::hex << entry_point << std::endl;
        std::cerr << "[LOAD] Loading binary at base address" << std::endl;
    }
    
    ctx_.setConcreteMemoryAreaValue(base_addr, binary_data);
    
    if (binary_format_->is_64bit()) {
        ctx_.setConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_RIP), 
                                      binary_format_->get_entry_point());
        ctx_.setConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_RSP), 
                                      0x7fffffffe000ULL);
    } else {
        ctx_.setConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_EIP), 
                                      static_cast<uint32_t>(binary_format_->get_entry_point()));
        ctx_.setConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_ESP), 
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
    
    // Track CLI arguments and environment variables
    if (io_tracker_) {
        for (const auto& arg : args_) {
            io_tracker_->track_cli_argument(arg);
        }
        for (const auto& env : env_vars_) {
            io_tracker_->track_environment_variable(env.first, env.second);
        }
    }
    
    try {
        int instruction_count = 0;
        while (true) {
            auto current_time = std::chrono::steady_clock::now();
            if (current_time - start_time > timeout) {
                std::cout << "Execution timeout reached" << std::endl;
                break;
            }
            
            triton::uint64 pc;
            if (binary_format_->is_64bit()) {
                pc = static_cast<triton::uint64>(ctx_.getConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_RIP)));
            } else {
                pc = static_cast<triton::uint64>(ctx_.getConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_EIP)));
            }
            
            auto instruction = triton::arch::Instruction();
            instruction.setAddress(pc);
            
            auto opcodes = ctx_.getConcreteMemoryAreaValue(pc, 16);
            instruction.setOpcode(opcodes.data(), opcodes.size());
            
            // Add detailed debugging for instruction processing
            if (verbosity_level_ > 1) {
                std::cerr << "[DEBUG] Attempting to process instruction at PC: 0x" << std::hex << pc << std::endl;
                std::cerr << "[DEBUG] Opcodes (" << std::dec << opcodes.size() << " bytes): ";
                for (size_t i = 0; i < std::min(opcodes.size(), (size_t)8); ++i) {
                    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (unsigned)opcodes[i] << " ";
                }
                std::cerr << std::endl;
                std::cerr << "[DEBUG] Instruction disassembly: " << instruction.getDisassembly() << std::endl;
            }
            
            if (!ctx_.processing(instruction)) {
                auto disasm = instruction.getDisassembly();
                
                // Check if this is an unsupported CET instruction we can skip
                if (disasm.find("endbr64") != std::string::npos || disasm.find("endbr32") != std::string::npos) {
                    if (verbosity_level_ > 1) {
                        std::cerr << "[SKIP] Unsupported CET instruction: " << disasm << " at 0x" << std::hex << pc << std::endl;
                    }
                    // Skip this instruction by advancing PC manually
                    uint64_t next_pc = pc + instruction.getSize();
                    if (binary_format_->is_64bit()) {
                        ctx_.setConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_RIP), next_pc);
                    } else {
                        ctx_.setConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_EIP), static_cast<uint32_t>(next_pc));
                    }
                    continue; // Continue to next instruction
                }
                
                std::cerr << "INSTRUCTION PROCESSING FAILED at PC: 0x" << std::hex << pc << std::endl;
                std::cerr << "Instruction bytes: ";
                for (size_t i = 0; i < std::min(opcodes.size(), (size_t)8); ++i) {
                    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (unsigned)opcodes[i] << " ";
                }
                std::cerr << std::endl;
                std::cerr << "Disassembly: " << disasm << std::endl;
                std::cerr << "Size: " << std::dec << instruction.getSize() << " bytes" << std::endl;
                std::cerr << "Type: " << instruction.getType() << std::endl;
                std::cerr << "Execution finished or invalid instruction after " << instruction_count << " instructions" << std::endl;
                break;
            }
            
            instruction_count++;
            check_syscall(instruction);
            log_instruction(instruction, verbosity_level_);
            
            // Limit instruction count to prevent infinite loops
            if (instruction_count > 10000) {
                std::cout << "Instruction limit reached" << std::endl;
                break;
            }
            
            std::this_thread::sleep_for(std::chrono::microseconds(1));
        }
    } catch (const std::exception& e) {
        std::cerr << "Execution error: " << e.what() << std::endl;
    }
}

void TritonEngine::memory_callback(triton::Context& ctx, const triton::arch::MemoryAccess& mem) {
    if (io_tracker_) {
        io_tracker_->track_memory_access(mem.getAddress(), mem.getSize(), mem.getType());
    }
}

void TritonEngine::check_syscall(const triton::arch::Instruction& instruction) {
    if (!io_tracker_) return;
    
    auto mnemonic = instruction.getDisassembly();
    
    if (binary_format_->is_64bit()) {
        if (mnemonic.find("syscall") != std::string::npos) {
            auto rax = ctx_.getConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_RAX));
            auto rax_val = static_cast<uint64_t>(rax);
            io_tracker_->track_syscall(rax_val, "syscall_" + std::to_string(rax_val));
        }
    } else {
        if (mnemonic.find("int") != std::string::npos && mnemonic.find("0x80") != std::string::npos) {
            auto eax = ctx_.getConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_EAX));
            auto eax_val = static_cast<uint64_t>(eax);
            io_tracker_->track_syscall(eax_val, "int80_" + std::to_string(eax_val));
        }
    }
}

void TritonEngine::log_instruction(const triton::arch::Instruction& instruction, int verbosity_level) {
    if (verbosity_level < 2) return;
    
    auto mnemonic = instruction.getDisassembly();
    auto address = instruction.getAddress();
    
    std::cerr << "[INSTRUCTION] 0x" << std::hex << address << ": " << mnemonic;
    
    // Add syscall detection info for -vvv
    if (verbosity_level > 2) {
        if (binary_format_->is_64bit()) {
            if (mnemonic.find("syscall") != std::string::npos) {
                auto rax = ctx_.getConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_RAX));
                auto rax_val = static_cast<uint64_t>(rax);
                std::cerr << " [SYSCALL DETECTED: rax=" << std::dec << rax_val << "]";
            }
        } else {
            if (mnemonic.find("int") != std::string::npos && mnemonic.find("0x80") != std::string::npos) {
                auto eax = ctx_.getConcreteRegisterValue(ctx_.getRegister(triton::arch::ID_REG_X86_EAX));
                auto eax_val = static_cast<uint64_t>(eax);
                std::cerr << " [INT80 DETECTED: eax=" << std::dec << eax_val << "]";
            }
        }
    }
    
    std::cerr << std::endl;
}