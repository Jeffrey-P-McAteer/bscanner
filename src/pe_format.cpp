#include "pe_format.h"
#include <fstream>
#include <stdexcept>

#ifndef _WIN32
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    struct {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    } FileHeader;
    struct {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint32_t BaseOfData;
        uint32_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint32_t SizeOfStackReserve;
        uint32_t SizeOfStackCommit;
        uint32_t SizeOfHeapReserve;
        uint32_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
    } OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    struct {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    } FileHeader;
    struct {
        uint16_t Magic;
        uint8_t MajorLinkerVersion;
        uint8_t MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
    } OptionalHeader;
};

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#endif

PeFormat::PeFormat(const std::string& path) 
    : BinaryFormat(path), is_64bit_(false), entry_point_(0), base_address_(0) {
    parse_pe_header();
}

void PeFormat::parse_pe_header() {
    std::ifstream file(path_, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open PE file: " + path_);
    }
    
    IMAGE_DOS_HEADER dos_header;
    file.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
    
    if (dos_header.e_magic != 0x5A4D) {
        throw std::runtime_error("Invalid DOS header");
    }
    
    file.seekg(dos_header.e_lfanew);
    
    uint32_t signature;
    file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    
    if (signature != 0x00004550) {
        throw std::runtime_error("Invalid PE signature");
    }
    
    file.seekg(dos_header.e_lfanew + 4 + 20);
    
    uint16_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is_64bit_ = true;
        file.seekg(dos_header.e_lfanew);
        IMAGE_NT_HEADERS64 nt_headers;
        file.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));
        entry_point_ = nt_headers.OptionalHeader.AddressOfEntryPoint;
        base_address_ = nt_headers.OptionalHeader.ImageBase;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        is_64bit_ = false;
        file.seekg(dos_header.e_lfanew);
        IMAGE_NT_HEADERS32 nt_headers;
        file.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));
        entry_point_ = nt_headers.OptionalHeader.AddressOfEntryPoint;
        base_address_ = nt_headers.OptionalHeader.ImageBase;
    } else {
        throw std::runtime_error("Unsupported PE format");
    }
}

uint64_t PeFormat::get_entry_point() const {
    return base_address_ + entry_point_;
}

uint64_t PeFormat::get_base_address() const {
    return base_address_;
}

bool PeFormat::is_64bit() const {
    return is_64bit_;
}

void PeFormat::load_sections() {
}