#include "binary_analyzer.h"
#include "elf_format.h"
#include "pe_format.h"
#include <iostream>
#include <fstream>
#include <stdexcept>

BinaryAnalyzer::BinaryAnalyzer(const AnalysisConfig& config) 
    : config_(config) {
    detect_binary_format();
    setup_triton_engine();
    io_tracker_ = std::make_unique<IOTracker>(config_.verbosity_level);
}

BinaryAnalyzer::~BinaryAnalyzer() = default;

void BinaryAnalyzer::analyze() {
    if (config_.verbosity_level > 0) {
        std::cout << "Starting analysis of: " << config_.target_binary << std::endl;
    }
    
    run_analysis();
    generate_report();
}

void BinaryAnalyzer::detect_binary_format() {
    std::ifstream file(config_.target_binary, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open binary file: " + config_.target_binary);
    }
    
    char magic[4];
    file.read(magic, 4);
    
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        binary_format_ = std::make_unique<ElfFormat>(config_.target_binary);
        if (config_.verbosity_level > 0) {
            std::cout << "Detected ELF format" << std::endl;
        }
    } else if (magic[0] == 'M' && magic[1] == 'Z') {
        binary_format_ = std::make_unique<PeFormat>(config_.target_binary);
        if (config_.verbosity_level > 0) {
            std::cout << "Detected PE format" << std::endl;
        }
    } else {
        throw std::runtime_error("Unsupported binary format");
    }
}

void BinaryAnalyzer::setup_triton_engine() {
    triton_engine_ = std::make_unique<TritonEngine>(binary_format_.get(), config_.verbosity_level);
}

void BinaryAnalyzer::run_analysis() {
    triton_engine_->load_binary();
    triton_engine_->set_environment(config_.env_vars);
    triton_engine_->set_arguments(config_.cli_args);
    triton_engine_->set_io_tracker(io_tracker_.get());
    
    triton_engine_->execute_with_timeout(config_.timeout_seconds);
}

void BinaryAnalyzer::generate_report() {
    auto input_map = io_tracker_->get_input_mappings();
    auto output_map = io_tracker_->get_output_mappings();
    
    if (config_.output_format == "json") {
        io_tracker_->output_json_report(std::cout);
    } else if (config_.output_format == "xml") {
        io_tracker_->output_xml_report(std::cout);
    } else {
        io_tracker_->output_text_report(std::cout);
    }
}