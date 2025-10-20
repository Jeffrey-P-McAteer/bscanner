#pragma once
#include "binary_format.h"
#include <elf.h>
#include <vector>

class ElfFormat : public BinaryFormat {
public:
    explicit ElfFormat(const std::string& path);
    ~ElfFormat() override = default;
    
    BinaryType get_type() const override { return BinaryType::ELF; }
    uint64_t get_entry_point() const override;
    uint64_t get_base_address() const override;
    bool is_64bit() const override;
    void load_sections() override;

private:
    bool is_64bit_;
    uint64_t entry_point_;
    uint64_t base_address_;
    
    void parse_elf_header();
    void parse_elf32();
    void parse_elf64();
};