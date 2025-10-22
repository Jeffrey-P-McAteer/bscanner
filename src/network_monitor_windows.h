#pragma once

#ifdef _WIN32
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>

class WindowsNetworkMonitor {
public:
    struct NetworkEvent {
        enum Type {
            SOCKET_CREATE,
            SOCKET_BIND,
            SOCKET_LISTEN,
            SOCKET_ACCEPT,
            SOCKET_CONNECT,
            NETWORK_SEND,
            NETWORK_RECV,
            SOCKET_CLOSE
        };
        
        Type type;
        DWORD process_id;
        DWORD thread_id;
        SOCKET socket_handle;
        std::vector<uint8_t> data;
        size_t data_size;
        std::string source_address;
        std::string destination_address;
        uint16_t source_port;
        uint16_t destination_port;
        ULONGLONG timestamp;
    };

    using EventCallback = std::function<void(const NetworkEvent&)>;

    WindowsNetworkMonitor();
    ~WindowsNetworkMonitor();

    bool start_monitoring(DWORD target_process_id, EventCallback callback);
    void stop_monitoring();
    bool is_monitoring() const { return monitoring.load(); }

private:
    static VOID WINAPI event_record_callback(PEVENT_RECORD event_record);
    static ULONG WINAPI buffer_callback(PEVENT_TRACE_LOGFILE buffer);
    
    void process_event_record(PEVENT_RECORD event_record);
    void monitoring_thread();
    
    // ETW session management
    bool start_etw_session();
    void stop_etw_session();
    bool enable_winsock_provider();
    
    // Event parsing
    NetworkEvent parse_winsock_event(PEVENT_RECORD event_record);
    std::vector<uint8_t> extract_network_data(PEVENT_RECORD event_record);
    
    // Session data
    TRACEHANDLE session_handle;
    TRACEHANDLE trace_handle;
    EVENT_TRACE_LOGFILE trace_logfile;
    std::wstring session_name;
    
    // Monitoring state
    std::atomic<bool> monitoring;
    std::thread monitor_thread;
    DWORD target_pid;
    EventCallback event_callback;
    
    // Static instance for callbacks
    static WindowsNetworkMonitor* instance;
    
    // Constants
    static const GUID WINSOCK_PROVIDER_GUID;
    static const UCHAR WINSOCK_SEND_OPCODE;
    static const UCHAR WINSOCK_RECV_OPCODE;
    static const UCHAR WINSOCK_CONNECT_OPCODE;
    static const UCHAR WINSOCK_ACCEPT_OPCODE;
};

// Windows-specific network wrapper
class WindowsNetworkWrapper {
public:
    WindowsNetworkWrapper();
    ~WindowsNetworkWrapper();
    
    bool monitor_process(const std::string& executable_path);
    void stop_monitoring();
    
    // Get captured events in BScanner format
    std::vector<WindowsNetworkMonitor::NetworkEvent> get_network_events() const;
    
private:
    void on_network_event(const WindowsNetworkMonitor::NetworkEvent& event);
    
    std::unique_ptr<WindowsNetworkMonitor> monitor;
    std::vector<WindowsNetworkMonitor::NetworkEvent> captured_events;
    DWORD target_process_id;
};

#endif // _WIN32