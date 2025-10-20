#include "elf_format.h"
#include <fstream>
#include <stdexcept>
#include <cstring>

ElfFormat::ElfFormat(const std::string& path) 
    : BinaryFormat(path), is_64bit_(false), entry_point_(0), base_address_(0) {
    parse_elf_header();
}

void ElfFormat::parse_elf_header() {
    std::ifstream file(path_, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open ELF file: " + path_);
    }
    
    unsigned char e_ident[EI_NIDENT];
    file.read(reinterpret_cast<char*>(e_ident), EI_NIDENT);
    
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        is_64bit_ = true;
        parse_elf64();
    } else if (e_ident[EI_CLASS] == ELFCLASS32) {
        is_64bit_ = false;
        parse_elf32();
    } else {
        throw std::runtime_error("Invalid ELF class");
    }
}

void ElfFormat::parse_elf32() {
    std::ifstream file(path_, std::ios::binary);
    file.seekg(0);
    
    Elf32_Ehdr header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    entry_point_ = header.e_entry;
    base_address_ = 0x08048000;
}

void ElfFormat::parse_elf64() {
    std::ifstream file(path_, std::ios::binary);
    file.seekg(0);
    
    Elf64_Ehdr header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    entry_point_ = header.e_entry;
    // For PIE executables, use the base address from the first LOAD segment
    // For now, we'll use 0x400000 and adjust the entry point accordingly
    base_address_ = 0x400000;
    
    // If this is a PIE executable with entry point < base_address,
    // adjust the entry point to be relative to the base address
    if (header.e_type == ET_DYN && entry_point_ < base_address_) {
        entry_point_ += base_address_;
    }
}

uint64_t ElfFormat::get_entry_point() const {
    return entry_point_;
}

uint64_t ElfFormat::get_base_address() const {
    return base_address_;
}

bool ElfFormat::is_64bit() const {
    return is_64bit_;
}

void ElfFormat::load_sections() {
}