#pragma once
#include <string>
#include <cstdint>

enum class BinaryType {
    ELF,
    PE
};

class BinaryFormat {
public:
    explicit BinaryFormat(const std::string& path) : path_(path) {}
    virtual ~BinaryFormat() = default;
    
    virtual BinaryType get_type() const = 0;
    virtual uint64_t get_entry_point() const = 0;
    virtual uint64_t get_base_address() const = 0;
    virtual bool is_64bit() const = 0;
    virtual void load_sections() = 0;
    
    const std::string& get_path() const { return path_; }

protected:
    std::string path_;
};