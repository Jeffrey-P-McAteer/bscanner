#include "io_tracker.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

IOTracker::IOTracker() : current_timestamp_(0), verbosity_level_(0) {}

IOTracker::IOTracker(int verbosity_level) : current_timestamp_(0), verbosity_level_(verbosity_level) {}

IOTracker::~IOTracker() = default;

void IOTracker::track_memory_access(uint64_t address, size_t size, int access_type) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_memory_access] address=0x" << std::hex << address 
                  << ", size=" << std::dec << size << ", access_type=" << access_type << std::endl;
    }
}

void IOTracker::track_syscall(uint64_t syscall_number, const std::string& syscall_name) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_syscall] syscall_number=" << syscall_number 
                  << ", syscall_name=\"" << syscall_name << "\"" << std::endl;
    }
}

void IOTracker::track_file_operation(const std::string& filename, IOType type, const std::vector<uint8_t>& data) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_file_operation] filename=\"" << filename 
                  << "\", type=" << (type == IOType::FILE_READ ? "FILE_READ" : "FILE_WRITE")
                  << ", data_size=" << data.size() << std::endl;
    }
    if (type == IOType::FILE_READ) {
        add_event(type, filename, "", data);
    } else if (type == IOType::FILE_WRITE) {
        add_event(type, "", filename, data);
    }
}

void IOTracker::track_network_operation(const std::string& endpoint, IOType type, const std::vector<uint8_t>& data) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_network_operation] endpoint=\"" << endpoint 
                  << "\", type=" << (type == IOType::NETWORK_READ ? "NETWORK_READ" : "NETWORK_WRITE")
                  << ", data_size=" << data.size() << std::endl;
    }
    if (type == IOType::NETWORK_READ) {
        add_event(type, endpoint, "", data);
    } else if (type == IOType::NETWORK_WRITE) {
        add_event(type, "", endpoint, data);
    }
}

void IOTracker::track_stdout_write(const std::vector<uint8_t>& data) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_stdout_write] data_size=" << data.size() << std::endl;
    }
    add_event(IOType::STDOUT_WRITE, "", "stdout", data);
}

void IOTracker::track_stderr_write(const std::vector<uint8_t>& data) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_stderr_write] data_size=" << data.size() << std::endl;
    }
    add_event(IOType::STDERR_WRITE, "", "stderr", data);
}

void IOTracker::track_cli_argument(const std::string& arg) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_cli_argument] arg=\"" << arg << "\"" << std::endl;
    }
    std::vector<uint8_t> arg_data(arg.begin(), arg.end());
    add_event(IOType::CLI_ARG, "command_line", "", arg_data);
}

void IOTracker::track_environment_variable(const std::string& name, const std::string& value) {
    if (verbosity_level_ > 2) {
        std::cerr << "[IOTracker::track_environment_variable] name=\"" << name 
                  << "\", value=\"" << value << "\"" << std::endl;
    }
    std::vector<uint8_t> value_data(value.begin(), value.end());
    add_event(IOType::ENV_VAR, name, "", value_data);
}

void IOTracker::add_event(IOType type, const std::string& source, const std::string& destination,
                         const std::vector<uint8_t>& data) {
    IOEvent event;
    event.type = type;
    event.source = source;
    event.destination = destination;
    event.data = data;
    event.timestamp = current_timestamp_++;
    event.instruction_address = 0;
    
    events_.push_back(event);
}

InputOutputMapping IOTracker::get_input_mappings() const {
    InputOutputMapping mapping;
    
    for (const auto& event : events_) {
        if (event.type == IOType::FILE_READ || event.type == IOType::NETWORK_READ ||
            event.type == IOType::CLI_ARG || event.type == IOType::ENV_VAR) {
            mapping.inputs.push_back(event);
        }
    }
    
    return mapping;
}

InputOutputMapping IOTracker::get_output_mappings() const {
    InputOutputMapping mapping;
    
    for (const auto& event : events_) {
        if (event.type == IOType::FILE_WRITE || event.type == IOType::NETWORK_WRITE ||
            event.type == IOType::STDOUT_WRITE || event.type == IOType::STDERR_WRITE) {
            mapping.outputs.push_back(event);
        }
    }
    
    return mapping;
}

void IOTracker::output_json_report(std::ostream& out) const {
    out << "{\n";
    out << "  \"analysis_results\": {\n";
    out << "    \"inputs\": [\n";
    
    auto input_mapping = get_input_mappings();
    for (size_t i = 0; i < input_mapping.inputs.size(); ++i) {
        const auto& event = input_mapping.inputs[i];
        out << "      {\n";
        out << "        \"type\": \"";
        switch (event.type) {
            case IOType::FILE_READ: out << "file_read"; break;
            case IOType::NETWORK_READ: out << "network_read"; break;
            case IOType::CLI_ARG: out << "cli_argument"; break;
            case IOType::ENV_VAR: out << "environment_variable"; break;
            default: out << "unknown"; break;
        }
        out << "\",\n";
        out << "        \"source\": \"" << escape_json_string(event.source) << "\",\n";
        out << "        \"data_hex\": \"" << data_to_hex_string(event.data) << "\",\n";
        
        // Try to decode as UTF-8 string
        std::string utf8_string = data_to_utf8_string(event.data);
        if (!utf8_string.empty()) {
            out << "        \"data_string_first_1024\": \"" << escape_json_string(utf8_string) << "\",\n";
        }
        
        out << "        \"timestamp\": " << event.timestamp << "\n";
        out << "      }";
        if (i + 1 < input_mapping.inputs.size()) out << ",";
        out << "\n";
    }
    
    out << "    ],\n";
    out << "    \"outputs\": [\n";
    
    auto output_mapping = get_output_mappings();
    for (size_t i = 0; i < output_mapping.outputs.size(); ++i) {
        const auto& event = output_mapping.outputs[i];
        out << "      {\n";
        out << "        \"type\": \"";
        switch (event.type) {
            case IOType::FILE_WRITE: out << "file_write"; break;
            case IOType::NETWORK_WRITE: out << "network_write"; break;
            case IOType::STDOUT_WRITE: out << "stdout_write"; break;
            case IOType::STDERR_WRITE: out << "stderr_write"; break;
            default: out << "unknown"; break;
        }
        out << "\",\n";
        out << "        \"destination\": \"" << escape_json_string(event.destination) << "\",\n";
        out << "        \"data_hex\": \"" << data_to_hex_string(event.data) << "\",\n";
        
        // Try to decode as UTF-8 string
        std::string utf8_string = data_to_utf8_string(event.data);
        if (!utf8_string.empty()) {
            out << "        \"data_string_first_1024\": \"" << escape_json_string(utf8_string) << "\",\n";
        }
        
        out << "        \"timestamp\": " << event.timestamp << "\n";
        out << "      }";
        if (i + 1 < output_mapping.outputs.size()) out << ",";
        out << "\n";
    }
    
    out << "    ]\n";
    out << "  }\n";
    out << "}\n";
}

void IOTracker::output_xml_report(std::ostream& out) const {
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<analysis_results>\n";
    out << "  <inputs>\n";
    
    auto input_mapping = get_input_mappings();
    for (const auto& event : input_mapping.inputs) {
        out << "    <input>\n";
        out << "      <type>";
        switch (event.type) {
            case IOType::FILE_READ: out << "file_read"; break;
            case IOType::NETWORK_READ: out << "network_read"; break;
            case IOType::CLI_ARG: out << "cli_argument"; break;
            case IOType::ENV_VAR: out << "environment_variable"; break;
            default: out << "unknown"; break;
        }
        out << "</type>\n";
        out << "      <source>" << escape_xml_string(event.source) << "</source>\n";
        out << "      <data_hex>" << data_to_hex_string(event.data) << "</data_hex>\n";
        
        // Try to decode as UTF-8 string
        std::string utf8_string = data_to_utf8_string(event.data);
        if (!utf8_string.empty()) {
            out << "      <data_string_first_1024>" << escape_xml_string(utf8_string) << "</data_string_first_1024>\n";
        }
        
        out << "      <timestamp>" << event.timestamp << "</timestamp>\n";
        out << "    </input>\n";
    }
    
    out << "  </inputs>\n";
    out << "  <outputs>\n";
    
    auto output_mapping = get_output_mappings();
    for (const auto& event : output_mapping.outputs) {
        out << "    <output>\n";
        out << "      <type>";
        switch (event.type) {
            case IOType::FILE_WRITE: out << "file_write"; break;
            case IOType::NETWORK_WRITE: out << "network_write"; break;
            case IOType::STDOUT_WRITE: out << "stdout_write"; break;
            case IOType::STDERR_WRITE: out << "stderr_write"; break;
            default: out << "unknown"; break;
        }
        out << "</type>\n";
        out << "      <destination>" << escape_xml_string(event.destination) << "</destination>\n";
        out << "      <data_hex>" << data_to_hex_string(event.data) << "</data_hex>\n";
        
        // Try to decode as UTF-8 string
        std::string utf8_string = data_to_utf8_string(event.data);
        if (!utf8_string.empty()) {
            out << "      <data_string_first_1024>" << escape_xml_string(utf8_string) << "</data_string_first_1024>\n";
        }
        
        out << "      <timestamp>" << event.timestamp << "</timestamp>\n";
        out << "    </output>\n";
    }
    
    out << "  </outputs>\n";
    out << "</analysis_results>\n";
}

void IOTracker::output_text_report(std::ostream& out) const {
    out << "BScanner Analysis Report\n";
    out << "========================\n\n";
    
    out << "INPUTS:\n";
    out << "-------\n";
    auto input_mapping = get_input_mappings();
    for (const auto& event : input_mapping.inputs) {
        out << "Type: ";
        switch (event.type) {
            case IOType::FILE_READ: out << "File Read"; break;
            case IOType::NETWORK_READ: out << "Network Read"; break;
            case IOType::CLI_ARG: out << "CLI Argument"; break;
            case IOType::ENV_VAR: out << "Environment Variable"; break;
            default: out << "Unknown"; break;
        }
        out << "\n";
        out << "Source: " << event.source << "\n";
        out << "Data: " << data_to_hex_string(event.data) << "\n";
        
        // Try to decode as UTF-8 string
        std::string utf8_string = data_to_utf8_string(event.data);
        if (!utf8_string.empty()) {
            out << "Data (UTF-8): " << utf8_string << "\n";
        }
        
        out << "Timestamp: " << event.timestamp << "\n\n";
    }
    
    out << "OUTPUTS:\n";
    out << "--------\n";
    auto output_mapping = get_output_mappings();
    for (const auto& event : output_mapping.outputs) {
        out << "Type: ";
        switch (event.type) {
            case IOType::FILE_WRITE: out << "File Write"; break;
            case IOType::NETWORK_WRITE: out << "Network Write"; break;
            case IOType::STDOUT_WRITE: out << "Stdout Write"; break;
            case IOType::STDERR_WRITE: out << "Stderr Write"; break;
            default: out << "Unknown"; break;
        }
        out << "\n";
        out << "Destination: " << event.destination << "\n";
        out << "Data: " << data_to_hex_string(event.data) << "\n";
        
        // Try to decode as UTF-8 string
        std::string utf8_string = data_to_utf8_string(event.data);
        if (!utf8_string.empty()) {
            out << "Data (UTF-8): " << utf8_string << "\n";
        }
        
        out << "Timestamp: " << event.timestamp << "\n\n";
    }
}

std::string IOTracker::escape_json_string(const std::string& str) const {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c; break;
        }
    }
    return result;
}

std::string IOTracker::escape_xml_string(const std::string& str) const {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result += c; break;
        }
    }
    return result;
}

std::string IOTracker::data_to_hex_string(const std::vector<uint8_t>& data) const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string IOTracker::data_to_utf8_string(const std::vector<uint8_t>& data, size_t max_length) const {
    if (data.empty()) {
        return "";
    }
    
    try {
        // Attempt to decode as UTF-8
        std::string result;
        result.reserve(std::min(data.size(), max_length));
        
        for (size_t i = 0; i < data.size() && result.length() < max_length; ++i) {
            uint8_t byte = data[i];
            
            // Simple UTF-8 validation and decoding
            if (byte <= 0x7F) {
                // ASCII character (0xxxxxxx)
                result += static_cast<char>(byte);
            } else if ((byte & 0xE0) == 0xC0) {
                // 2-byte sequence (110xxxxx 10xxxxxx)
                if (i + 1 < data.size() && (data[i + 1] & 0xC0) == 0x80) {
                    result += static_cast<char>(byte);
                    result += static_cast<char>(data[++i]);
                } else {
                    return ""; // Invalid UTF-8 sequence
                }
            } else if ((byte & 0xF0) == 0xE0) {
                // 3-byte sequence (1110xxxx 10xxxxxx 10xxxxxx)
                if (i + 2 < data.size() && 
                    (data[i + 1] & 0xC0) == 0x80 && 
                    (data[i + 2] & 0xC0) == 0x80) {
                    result += static_cast<char>(byte);
                    result += static_cast<char>(data[++i]);
                    result += static_cast<char>(data[++i]);
                } else {
                    return ""; // Invalid UTF-8 sequence
                }
            } else if ((byte & 0xF8) == 0xF0) {
                // 4-byte sequence (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
                if (i + 3 < data.size() && 
                    (data[i + 1] & 0xC0) == 0x80 && 
                    (data[i + 2] & 0xC0) == 0x80 && 
                    (data[i + 3] & 0xC0) == 0x80) {
                    result += static_cast<char>(byte);
                    result += static_cast<char>(data[++i]);
                    result += static_cast<char>(data[++i]);
                    result += static_cast<char>(data[++i]);
                } else {
                    return ""; // Invalid UTF-8 sequence
                }
            } else {
                return ""; // Invalid UTF-8 start byte
            }
        }
        
        return result;
    } catch (const std::exception& e) {
        return ""; // Failed to decode as UTF-8
    }
}