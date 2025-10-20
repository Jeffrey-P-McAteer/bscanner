
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







