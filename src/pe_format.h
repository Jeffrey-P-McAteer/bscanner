#pragma once
#include "binary_format.h"
#include <windows.h>

class PeFormat : public BinaryFormat {
public:
    explicit PeFormat(const std::string& path);
    ~PeFormat() override = default;
    
    BinaryType get_type() const override { return BinaryType::PE; }
    uint64_t get_entry_point() const override;
    uint64_t get_base_address() const override;
    bool is_64bit() const override;
    void load_sections() override;

private:
    bool is_64bit_;
    uint64_t entry_point_;
    uint64_t base_address_;
    
    void parse_pe_header();
};