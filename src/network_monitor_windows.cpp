#ifdef _WIN32
#include "network_monitor_windows.h"
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <iostream>
#include <sstream>
#include <iomanip>

// Static member definitions
WindowsNetworkMonitor* WindowsNetworkMonitor::instance = nullptr;

// Microsoft-Windows-Winsock-AFD provider GUID
const GUID WindowsNetworkMonitor::WINSOCK_PROVIDER_GUID = 
    { 0xe53c6823, 0x7bb8, 0x44bb, { 0x90, 0xdc, 0x3f, 0x86, 0xd9, 0xa7, 0x0e, 0xd5 } };

// Winsock event opcodes
const UCHAR WindowsNetworkMonitor::WINSOCK_SEND_OPCODE = 10;
const UCHAR WindowsNetworkMonitor::WINSOCK_RECV_OPCODE = 11;
const UCHAR WindowsNetworkMonitor::WINSOCK_CONNECT_OPCODE = 12;
const UCHAR WindowsNetworkMonitor::WINSOCK_ACCEPT_OPCODE = 13;

WindowsNetworkMonitor::WindowsNetworkMonitor()
    : session_handle(INVALID_PROCESSTRACE_HANDLE)
    , trace_handle(INVALID_PROCESSTRACE_HANDLE)
    , monitoring(false)
    , target_pid(0)
    , session_name(L"BScanner_Network_Session") {
    
    // Set static instance for callbacks
    instance = this;
    
    // Initialize trace logfile structure
    ZeroMemory(&trace_logfile, sizeof(EVENT_TRACE_LOGFILE));
    trace_logfile.LoggerName = const_cast<LPWSTR>(session_name.c_str());
    trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace_logfile.EventRecordCallback = event_record_callback;
    trace_logfile.BufferCallback = buffer_callback;
}

WindowsNetworkMonitor::~WindowsNetworkMonitor() {
    stop_monitoring();
    instance = nullptr;
}

bool WindowsNetworkMonitor::start_monitoring(DWORD target_process_id, EventCallback callback) {
    if (monitoring.load()) {
        return false; // Already monitoring
    }
    
    target_pid = target_process_id;
    event_callback = callback;
    
    // Start ETW session
    if (!start_etw_session()) {
        std::cerr << "Failed to start ETW session" << std::endl;
        return false;
    }
    
    // Enable Winsock provider
    if (!enable_winsock_provider()) {
        std::cerr << "Failed to enable Winsock provider" << std::endl;
        stop_etw_session();
        return false;
    }
    
    // Start monitoring thread
    monitoring.store(true);
    monitor_thread = std::thread(&WindowsNetworkMonitor::monitoring_thread, this);
    
    return true;
}

void WindowsNetworkMonitor::stop_monitoring() {
    if (!monitoring.load()) {
        return;
    }
    
    monitoring.store(false);
    
    // Stop ETW session
    stop_etw_session();
    
    // Wait for monitoring thread to finish
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }
}

bool WindowsNetworkMonitor::start_etw_session() {
    // Calculate buffer size for EVENT_TRACE_PROPERTIES + session name
    ULONG buffer_size = sizeof(EVENT_TRACE_PROPERTIES) + (session_name.length() + 1) * sizeof(WCHAR);
    
    // Allocate and initialize properties structure
    auto properties = std::make_unique<BYTE[]>(buffer_size);
    auto etw_properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(properties.get());
    
    ZeroMemory(etw_properties, buffer_size);
    etw_properties->Wnode.BufferSize = buffer_size;
    etw_properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    etw_properties->Wnode.ClientContext = 1; // Use QueryPerformanceCounter for timestamps
    etw_properties->Wnode.Guid = GUID{0}; // Will be set by StartTrace
    etw_properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    etw_properties->MaximumFileSize = 100; // MB
    etw_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    etw_properties->BufferSize = 64; // KB
    etw_properties->MinimumBuffers = 4;
    etw_properties->MaximumBuffers = 16;
    
    // Copy session name
    wcscpy_s(reinterpret_cast<PWSTR>(properties.get() + etw_properties->LoggerNameOffset),
             session_name.length() + 1, session_name.c_str());
    
    // Start the trace session
    ULONG result = StartTrace(&session_handle, session_name.c_str(), etw_properties);
    if (result != ERROR_SUCCESS) {
        if (result == ERROR_ALREADY_EXISTS) {
            // Stop existing session and try again
            ControlTrace(NULL, session_name.c_str(), etw_properties, EVENT_TRACE_CONTROL_STOP);
            result = StartTrace(&session_handle, session_name.c_str(), etw_properties);
        }
        
        if (result != ERROR_SUCCESS) {
            std::cerr << "StartTrace failed with error: " << result << std::endl;
            return false;
        }
    }
    
    return true;
}

void WindowsNetworkMonitor::stop_etw_session() {
    if (session_handle != INVALID_PROCESSTRACE_HANDLE) {
        // Calculate buffer size for EVENT_TRACE_PROPERTIES + session name
        ULONG buffer_size = sizeof(EVENT_TRACE_PROPERTIES) + (session_name.length() + 1) * sizeof(WCHAR);
        auto properties = std::make_unique<BYTE[]>(buffer_size);
        auto etw_properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(properties.get());
        
        ZeroMemory(etw_properties, buffer_size);
        etw_properties->Wnode.BufferSize = buffer_size;
        etw_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        
        ControlTrace(session_handle, nullptr, etw_properties, EVENT_TRACE_CONTROL_STOP);
        session_handle = INVALID_PROCESSTRACE_HANDLE;
    }
    
    if (trace_handle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(trace_handle);
        trace_handle = INVALID_PROCESSTRACE_HANDLE;
    }
}

bool WindowsNetworkMonitor::enable_winsock_provider() {
    // Enable the Winsock provider for our session
    ULONG result = EnableTraceEx2(session_handle, &WINSOCK_PROVIDER_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    
    if (result != ERROR_SUCCESS) {
        std::cerr << "EnableTraceEx2 failed with error: " << result << std::endl;
        return false;
    }
    
    return true;
}

void WindowsNetworkMonitor::monitoring_thread() {
    // Open trace for real-time processing
    trace_handle = OpenTrace(&trace_logfile);
    if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "OpenTrace failed with error: " << GetLastError() << std::endl;
        return;
    }
    
    // Process trace events
    ULONG result = ProcessTrace(&trace_handle, 1, nullptr, nullptr);
    if (result != ERROR_SUCCESS && result != ERROR_CANCELLED) {
        std::cerr << "ProcessTrace failed with error: " << result << std::endl;
    }
}

VOID WINAPI WindowsNetworkMonitor::event_record_callback(PEVENT_RECORD event_record) {
    if (instance) {
        instance->process_event_record(event_record);
    }
}

ULONG WINAPI WindowsNetworkMonitor::buffer_callback(PEVENT_TRACE_LOGFILE buffer) {
    // Continue processing
    return instance && instance->monitoring.load() ? TRUE : FALSE;
}

void WindowsNetworkMonitor::process_event_record(PEVENT_RECORD event_record) {
    // Check if this event is from our target process
    if (target_pid != 0 && event_record->EventHeader.ProcessId != target_pid) {
        return;
    }
    
    // Check if this is a Winsock event
    if (!IsEqualGUID(event_record->EventHeader.ProviderId, WINSOCK_PROVIDER_GUID)) {
        return;
    }
    
    // Parse the network event
    try {
        NetworkEvent net_event = parse_winsock_event(event_record);
        
        // Call the event callback
        if (event_callback) {
            event_callback(net_event);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing network event: " << e.what() << std::endl;
    }
}

WindowsNetworkMonitor::NetworkEvent WindowsNetworkMonitor::parse_winsock_event(PEVENT_RECORD event_record) {
    NetworkEvent event;
    
    // Fill basic event information
    event.process_id = event_record->EventHeader.ProcessId;
    event.thread_id = event_record->EventHeader.ThreadId;
    event.timestamp = event_record->EventHeader.TimeStamp.QuadPart;
    
    // Determine event type based on opcode
    switch (event_record->EventHeader.EventDescriptor.Opcode) {
        case WINSOCK_SEND_OPCODE:
            event.type = NetworkEvent::NETWORK_SEND;
            break;
        case WINSOCK_RECV_OPCODE:
            event.type = NetworkEvent::NETWORK_RECV;
            break;
        case WINSOCK_CONNECT_OPCODE:
            event.type = NetworkEvent::SOCKET_CONNECT;
            break;
        case WINSOCK_ACCEPT_OPCODE:
            event.type = NetworkEvent::SOCKET_ACCEPT;
            break;
        default:
            event.type = NetworkEvent::SOCKET_CREATE; // Default fallback
            break;
    }
    
    // Extract network data if present
    if (event.type == NetworkEvent::NETWORK_SEND || event.type == NetworkEvent::NETWORK_RECV) {
        event.data = extract_network_data(event_record);
        event.data_size = event.data.size();
    }
    
    return event;
}

std::vector<uint8_t> WindowsNetworkMonitor::extract_network_data(PEVENT_RECORD event_record) {
    std::vector<uint8_t> data;
    
    // Parse event data using TDH (Trace Data Helper)
    ULONG buffer_size = 0;
    TDHSTATUS status = TdhGetEventInformation(event_record, 0, nullptr, nullptr, &buffer_size);
    
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        auto buffer = std::make_unique<BYTE[]>(buffer_size);
        auto event_info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
        
        status = TdhGetEventInformation(event_record, 0, nullptr, event_info, &buffer_size);
        if (status == ERROR_SUCCESS) {
            // Look for data payload in event properties
            for (ULONG i = 0; i < event_info->PropertyCount; i++) {
                EVENT_PROPERTY_INFO& prop = event_info->EventPropertyInfoArray[i];
                
                // Check if this property contains network data
                PWSTR prop_name = reinterpret_cast<PWSTR>(buffer.get() + prop.NameOffset);
                if (wcscmp(prop_name, L"Data") == 0 || wcscmp(prop_name, L"Buffer") == 0) {
                    // Extract the data
                    PROPERTY_DATA_DESCRIPTOR descriptor;
                    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
                    descriptor.ArrayIndex = ULONG_MAX;
                    
                    ULONG data_size = 0;
                    status = TdhGetPropertySize(event_record, 0, nullptr, 1, &descriptor, &data_size);
                    
                    if (status == ERROR_SUCCESS && data_size > 0) {
                        data.resize(data_size);
                        status = TdhGetProperty(event_record, 0, nullptr, 1, &descriptor, data_size, data.data());
                        if (status == ERROR_SUCCESS) {
                            break;
                        }
                    }
                }
            }
        }
    }
    
    return data;
}

// WindowsNetworkWrapper implementation
WindowsNetworkWrapper::WindowsNetworkWrapper() 
    : target_process_id(0) {
    monitor = std::make_unique<WindowsNetworkMonitor>();
}

WindowsNetworkWrapper::~WindowsNetworkWrapper() {
    stop_monitoring();
}

bool WindowsNetworkWrapper::monitor_process(const std::string& executable_path) {
    // Launch the target process
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (!CreateProcessA(executable_path.c_str(), nullptr, nullptr, nullptr, FALSE, 
                       CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        return false;
    }
    
    target_process_id = pi.dwProcessId;
    
    // Start monitoring the process
    bool result = monitor->start_monitoring(target_process_id, 
        [this](const WindowsNetworkMonitor::NetworkEvent& event) {
            on_network_event(event);
        });
    
    // Clean up process handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return result;
}

void WindowsNetworkWrapper::stop_monitoring() {
    if (monitor) {
        monitor->stop_monitoring();
    }
}

std::vector<WindowsNetworkMonitor::NetworkEvent> WindowsNetworkWrapper::get_network_events() const {
    return captured_events;
}

void WindowsNetworkWrapper::on_network_event(const WindowsNetworkMonitor::NetworkEvent& event) {
    // Store the event
    captured_events.push_back(event);
    
    // Print event for debugging
    std::cout << "Network event: Type=" << event.type 
              << ", PID=" << event.process_id 
              << ", Data size=" << event.data_size << std::endl;
    
    // Print first 64 bytes of data in hex format
    if (!event.data.empty()) {
        std::cout << "Data: ";
        for (size_t i = 0; i < std::min(event.data.size(), size_t(64)); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<unsigned>(event.data[i]) << " ";
        }
        std::cout << std::dec << std::endl;
    }
}

#endif // _WIN32