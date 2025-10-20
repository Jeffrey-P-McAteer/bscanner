
# BScanner

`bscanner` is a small C++ command-line utility which uses the [Triton](https://triton-library.github.io)
dynamic binary analysis library to map primary and secondary inputs to executables to outputs.

Primary inputs are:

 - CLI arguments
 - Environment variables

Secondary inputs are:

 - File contents (typically read from hard-coded paths or CLI arguments or environment variables)
 - Network inputs (if the program makes a network call out and reads input to determine what do to next)

Outputs are:

 - Written file contents
 - Written network data

OS-specific capabilities such as unix sockets or filesystem FIFO queues are not analysed as the semantics of these are too detailed to be useful, and most software primarially interacts with other software using files and network calls.

# Building

Builds are run via `build.py` which downloads and compiles all dependencies before building `bscanner` itself. The tool is designed to be
platform agnostic, but cross-compilation is out of scope for the tool.

```bash
uv run build.py
```

To build and run an example program from `./example-programs/` you can use the following helper script

```bash
uv run build-and-run-example.py EXAMPLE_NAME EXAMPLE_BIN_ARG1 EXAMPLE_BIN_ARG2

# For example
uv run build-and-run-example.py example1 /tmp/test.txt
```

# Usage

```bash

# TODO document cli usage

```

# Useful Research

 - https://raw.githubusercontent.com/JonathanSalwan/Triton/master/publications/StHack2015_Dynamic_Behavior_Analysis_using_Binary_Instrumentation_Jonathan_Salwan.pdf
 - https://shell-storm.org/talks/SecurityDay2015_dynamic_symbolic_execution_Jonathan_Salwan.pdf







