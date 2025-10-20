# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BScanner is a C++ command-line utility that uses the Triton dynamic binary analysis library to map primary and secondary inputs to executables to outputs. It analyzes both ELF and PE32+ binaries cross-platform.

**Primary inputs**: CLI arguments, environment variables
**Secondary inputs**: File contents, network inputs
**Outputs**: Written file contents, written network data

## Development Commands

### Build
```bash
mkdir build && cd build
cmake .. -DTRITON_ROOT=/path/to/triton
make
```

### Install Triton (prerequisite)
Triton library must be installed before building. See https://triton-library.github.io for installation instructions.

### Run
```bash
./build/bscanner [OPTIONS] <binary>
./build/bscanner --help  # Show usage
./build/bscanner --env PATH=/usr/bin --args -v ./target_app
```

## Architecture

### Core Components

- **main.cpp**: Entry point and CLI orchestration
- **cli_parser.{h,cpp}**: Command-line argument parsing and configuration
- **binary_analyzer.{h,cpp}**: Main analysis orchestrator
- **binary_format.h**: Abstract base for binary format handlers
- **elf_format.{h,cpp}**: ELF binary format implementation
- **pe_format.{h,cpp}**: PE32+ binary format implementation  
- **triton_engine.{h,cpp}**: Triton library integration and execution engine
- **io_tracker.{h,cpp}**: Input/output event tracking and reporting

### Analysis Flow

1. Binary format detection (ELF vs PE32+)
2. Triton engine setup with appropriate architecture (x86/x86_64)
3. Binary loading and memory mapping
4. Dynamic execution with I/O tracking
5. Report generation (JSON/XML/text formats)

### Key Design Patterns

- Factory pattern for binary format detection
- Strategy pattern for different output formats
- Observer pattern for I/O event tracking during execution

## Dependencies

- **Triton**: Dynamic binary analysis framework (required)
- **CMake 3.15+**: Build system
- **C++17**: Language standard