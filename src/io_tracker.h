#pragma once
#include <map>
#include <vector>
#include <string>
#include <ostream>
#include <cstdint>

enum class IOType {
    FILE_READ,
    FILE_WRITE,
    NETWORK_READ,
    NETWORK_WRITE,
    STDOUT_WRITE,
    STDERR_WRITE,
    CLI_ARG,
    ENV_VAR
};

struct IOEvent {
    IOType type;
    std::string source;
    std::string destination;
    std::vector<uint8_t> data;
    uint64_t timestamp;
    uint64_t instruction_address;
};

struct InputOutputMapping {
    std::vector<IOEvent> inputs;
    std::vector<IOEvent> outputs;
    std::map<std::string, std::vector<std::string>> dependencies;
};

class IOTracker {
public:
    IOTracker();
    explicit IOTracker(int verbosity_level);
    ~IOTracker();
    
    void track_memory_access(uint64_t address, size_t size, int access_type);
    void track_syscall(uint64_t syscall_number, const std::string& syscall_name);
    void track_file_operation(const std::string& filename, IOType type, const std::vector<uint8_t>& data);
    void track_network_operation(const std::string& endpoint, IOType type, const std::vector<uint8_t>& data);
    void track_stdout_write(const std::vector<uint8_t>& data);
    void track_stderr_write(const std::vector<uint8_t>& data);
    void track_cli_argument(const std::string& arg);
    void track_environment_variable(const std::string& name, const std::string& value);
    
    InputOutputMapping get_input_mappings() const;
    InputOutputMapping get_output_mappings() const;
    
    void output_json_report(std::ostream& out) const;
    void output_xml_report(std::ostream& out) const;
    void output_text_report(std::ostream& out) const;

private:
    std::vector<IOEvent> events_;
    uint64_t current_timestamp_;
    int verbosity_level_;
    
    void add_event(IOType type, const std::string& source, const std::string& destination,
                   const std::vector<uint8_t>& data = {});
    std::string escape_json_string(const std::string& str) const;
    std::string escape_xml_string(const std::string& str) const;
    std::string data_to_hex_string(const std::vector<uint8_t>& data) const;
};