
#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
import shutil
import argparse
from pathlib import Path

REPO_DIR = Path(__file__).parent.absolute()
BUILD_DIR = REPO_DIR / "build"
TRITON_DIR = BUILD_DIR / "triton"
TRITON_BUILD_DIR = BUILD_DIR / "triton-build"
Z3_DIR = BUILD_DIR / "z3"
Z3_BUILD_DIR = BUILD_DIR / "z3-build"

TRITON_REPO_URL = "https://github.com/JonathanSalwan/Triton.git"
Z3_REPO_URL = "https://github.com/Z3Prover/z3.git"

def get_platform():
    """Detect the current platform."""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    else:
        raise RuntimeError(f"Unsupported platform: {system}. Only Linux and Windows are supported.")

def run_command(cmd, cwd=None, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    
    return result

def clone_triton():
    """Clone Triton source code from GitHub."""
    print("Cloning Triton from GitHub...")
    
    BUILD_DIR.mkdir(exist_ok=True)
    
    if TRITON_DIR.exists():
        print(f"Triton directory already exists at {TRITON_DIR}")
        # Update existing repository
        run_command(["git", "fetch", "--all"], cwd=TRITON_DIR)
        run_command(["git", "reset", "--hard", "origin/master"], cwd=TRITON_DIR)
        print("Updated Triton to latest master")
    else:
        # Clone repository
        run_command(["git", "clone", "--branch", "master", TRITON_REPO_URL, str(TRITON_DIR)])
        print(f"Cloned Triton to {TRITON_DIR}")

def clone_z3():
    """Clone Z3 source code from GitHub."""
    print("Cloning Z3 from GitHub...")
    
    BUILD_DIR.mkdir(exist_ok=True)
    
    if Z3_DIR.exists():
        print(f"Z3 directory already exists at {Z3_DIR}")
        # Update existing repository
        run_command(["git", "fetch", "--all"], cwd=Z3_DIR)
        run_command(["git", "reset", "--hard", "origin/master"], cwd=Z3_DIR)
        print("Updated Z3 to latest master")
    else:
        # Clone repository
        run_command(["git", "clone", "--branch", "master", Z3_REPO_URL, str(Z3_DIR)])
        print(f"Cloned Z3 to {Z3_DIR}")

def build_z3():
    """Build Z3 library."""
    print("Building Z3...")
    
    platform_name = get_platform()
    
    if Z3_BUILD_DIR.exists():
        shutil.rmtree(Z3_BUILD_DIR)
    Z3_BUILD_DIR.mkdir(parents=True)
    
    # Configure Z3 build
    cmake_cmd = [
        "cmake",
        str(Z3_DIR),
        f"-DCMAKE_INSTALL_PREFIX={Z3_BUILD_DIR / 'install'}",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DZ3_BUILD_LIBZ3_SHARED=ON"
    ]
    
    # Platform-specific configurations
    if platform_name == "windows":
        # Use latest Visual Studio generator
        cmake_cmd.extend(["-A", "x64"])
        # Try to find the best generator automatically
        generators = [
            "Visual Studio 17 2022",
            "Visual Studio 16 2019", 
            "Visual Studio 15 2017"
        ]
        
        generator_found = False
        for gen in generators:
            try:
                # Test if generator is available
                test_result = run_command(["cmake", "-G", gen, "--help"], check=False)
                if test_result.returncode == 0:
                    cmake_cmd.extend(["-G", gen])
                    generator_found = True
                    break
            except:
                continue
        
        if not generator_found:
            print("Warning: Could not find Visual Studio generator. Using default.")
    
    run_command(cmake_cmd, cwd=Z3_BUILD_DIR)
    
    # Build Z3
    build_cmd = ["cmake", "--build", ".", "--config", "Release"]
    if platform_name == "linux":
        build_cmd.extend(["-j", str(os.cpu_count() or 4)])
    elif platform_name == "windows":
        build_cmd.extend(["--parallel", str(os.cpu_count() or 4)])
    
    run_command(build_cmd, cwd=Z3_BUILD_DIR)
    
    # Install Z3
    install_cmd = ["cmake", "--install", ".", "--config", "Release"]
    run_command(install_cmd, cwd=Z3_BUILD_DIR)
    
    print(f"Z3 built and installed to {Z3_BUILD_DIR / 'install'}")

def install_triton_dependencies_linux():
    """Install Triton dependencies on Linux."""
    print("Installing Triton dependencies for Linux...")
    
    # Check if we can install dependencies automatically
    distro_commands = [
        # Ubuntu/Debian
        ["apt", "update"],
        ["apt", "install", "-y", "libcapstone-dev", "libboost-all-dev", "python3-dev", "libz3-dev"],
        # Alternative for systems without libz3-dev
        ["apt", "install", "-y", "libcapstone-dev", "libboost-all-dev", "python3-dev"]
    ]
    
    print("Note: You may need to install dependencies manually:")
    print("Ubuntu/Debian: sudo apt install libcapstone-dev libboost-all-dev python3-dev libz3-dev")
    print("CentOS/RHEL: sudo yum install capstone-devel boost-devel python3-devel")
    print("Arch: sudo pacman -S capstone boost python")

def build_triton():
    """Build Triton library."""
    print("Building Triton...")
    
    platform_name = get_platform()
    
    # Install dependencies if on Linux
    if platform_name == "linux":
        install_triton_dependencies_linux()
    
    if TRITON_BUILD_DIR.exists():
        shutil.rmtree(TRITON_BUILD_DIR)
    TRITON_BUILD_DIR.mkdir(parents=True)
    
    # Configure Triton build
    cmake_cmd = [
        "cmake",
        str(TRITON_DIR),
        f"-DCMAKE_INSTALL_PREFIX={TRITON_BUILD_DIR / 'install'}",
        "-DCMAKE_BUILD_TYPE=Release"
    ]
    
    # Platform-specific configurations
    if platform_name == "windows":
        # Use latest Visual Studio generator
        cmake_cmd.extend(["-A", "x64"])
        # Try to find the best generator automatically
        generators = [
            "Visual Studio 17 2022",
            "Visual Studio 16 2019", 
            "Visual Studio 15 2017"
        ]
        
        generator_found = False
        for gen in generators:
            try:
                test_cmd = cmake_cmd + ["-G", gen]
                run_command(test_cmd + ["--help"], check=False)
                cmake_cmd.extend(["-G", gen])
                generator_found = True
                break
            except:
                continue
        
        if not generator_found:
            print("Warning: Could not find Visual Studio generator. Using default.")
    
    elif platform_name == "linux":
        # Add Linux-specific optimizations
        cmake_cmd.extend([
            "-DBOOST_INTERFACE=ON",
            "-DPYTHON_INTERFACE=ON"
        ])
    
    # Configure Z3 paths (both platforms)
    z3_install_dir = Z3_BUILD_DIR / "install"
    if z3_install_dir.exists():
        z3_lib_dir = z3_install_dir / "lib"
        
        # Find the correct Z3 library file
        if platform_name == "windows":
            z3_lib_file = z3_lib_dir / "z3.lib"
            if not z3_lib_file.exists():
                z3_lib_file = z3_lib_dir / "libz3.lib"
        else:
            z3_lib_file = z3_lib_dir / "libz3.so"
            if not z3_lib_file.exists():
                z3_lib_file = z3_lib_dir / "libz3.a"
        
        cmake_cmd.extend([
            "-DZ3_INTERFACE=ON",
            f"-DZ3_INCLUDE_DIRS={z3_install_dir / 'include'}",
            f"-DZ3_LIBRARIES={z3_lib_file}"
        ])
        print(f"Using built Z3 library for Triton: {z3_lib_file}")
    else:
        print("Z3 not built, Triton will be built without Z3 interface")
    
    run_command(cmake_cmd, cwd=TRITON_BUILD_DIR)
    
    # Build Triton
    build_cmd = ["cmake", "--build", ".", "--config", "Release"]
    if platform_name == "linux":
        build_cmd.extend(["-j", str(os.cpu_count() or 4)])
    elif platform_name == "windows":
        # Use parallel build on Windows too
        build_cmd.extend(["--parallel", str(os.cpu_count() or 4)])
    
    run_command(build_cmd, cwd=TRITON_BUILD_DIR)
    
    # Install Triton
    install_cmd = ["cmake", "--install", ".", "--config", "Release"]
    run_command(install_cmd, cwd=TRITON_BUILD_DIR)
    
    print(f"Triton built and installed to {TRITON_BUILD_DIR / 'install'}")

def build_bscanner():
    """Build BScanner using the built Triton library."""
    print("Building BScanner...")
    
    bscanner_build_dir = BUILD_DIR / "bscanner-build"
    if bscanner_build_dir.exists():
        shutil.rmtree(bscanner_build_dir)
    bscanner_build_dir.mkdir(parents=True)
    
    triton_install_dir = TRITON_BUILD_DIR / "install"
    z3_install_dir = Z3_BUILD_DIR / "install"
    
    # Configure BScanner build
    cmake_cmd = [
        "cmake",
        str(REPO_DIR),
        f"-DTRITON_ROOT={triton_install_dir}",
        f"-DZ3_INCLUDE_DIR={z3_install_dir / 'include'}",
        "-DCMAKE_BUILD_TYPE=Release"
    ]
    
    platform_name = get_platform()
    if platform_name == "windows":
        cmake_cmd.extend(["-G", "Visual Studio 16 2019", "-A", "x64"])
    
    run_command(cmake_cmd, cwd=bscanner_build_dir)
    
    # Build BScanner
    build_cmd = ["cmake", "--build", ".", "--config", "Release"]
    if platform_name != "windows":
        build_cmd.extend(["-j", str(os.cpu_count() or 4)])
    
    run_command(build_cmd, cwd=bscanner_build_dir)
    
    # Copy executable to build root for easy access
    exe_name = "bscanner.exe" if platform_name == "windows" else "bscanner"
    if platform_name == "windows":
        exe_src = bscanner_build_dir / "Release" / exe_name
    else:
        exe_src = bscanner_build_dir / exe_name
    
    exe_dst = BUILD_DIR / exe_name
    if exe_src.exists():
        shutil.copy2(exe_src, exe_dst)
        print(f"BScanner executable copied to {exe_dst}")
    else:
        print(f"Warning: Could not find executable at {exe_src}")

def clean():
    """Remove all build artifacts and downloaded dependencies."""
    print("Cleaning build artifacts...")
    
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
        print(f"Removed {BUILD_DIR}")
    else:
        print("Build directory does not exist, nothing to clean")

def check_dependencies():
    """Check if required build tools are available."""
    required_tools = ["cmake", "git"]
    
    platform_name = get_platform()
    if platform_name == "windows":
        # On Windows, we need Visual Studio or Build Tools
        if not shutil.which("msbuild"):
            print("Error: MSBuild not found. Please install Visual Studio 2017 or later, or Build Tools for Visual Studio.")
            print("Download from: https://visualstudio.microsoft.com/downloads/")
            return False
    else:
        required_tools.extend(["make", "gcc"])
    
    missing_tools = []
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"Error: Missing required tools: {', '.join(missing_tools)}")
        if platform_name == "linux":
            print("Install with: sudo apt install cmake git build-essential")
        return False
    
    print("All required build tools are available.")
    return True

def main():
    parser = argparse.ArgumentParser(description="Build BScanner with automatic Triton dependency management")
    parser.add_argument("command", nargs="?", default="build", choices=["build", "clean"],
                       help="Command to execute (default: build)")
    parser.add_argument("--force-clone", action="store_true",
                       help="Force re-clone of Triton even if it exists")
    parser.add_argument("--force-rebuild", action="store_true",
                       help="Force rebuild of Triton even if it's already built")
    
    args = parser.parse_args()
    
    if args.command == "clean":
        clean()
        return
    
    if not check_dependencies():
        sys.exit(1)
    
    try:
        # Clone Z3 if needed
        if args.force_clone or not Z3_DIR.exists():
            if Z3_DIR.exists() and args.force_clone:
                shutil.rmtree(Z3_DIR)
            clone_z3()
        else:
            print(f"Z3 source already exists at {Z3_DIR}")
        
        # Build Z3 if needed
        z3_install_dir = Z3_BUILD_DIR / "install"
        if args.force_rebuild or not z3_install_dir.exists():
            build_z3()
        else:
            print(f"Z3 already built at {z3_install_dir}")
        
        # Clone Triton if needed
        if args.force_clone or not TRITON_DIR.exists():
            if TRITON_DIR.exists() and args.force_clone:
                shutil.rmtree(TRITON_DIR)
            clone_triton()
        else:
            print(f"Triton source already exists at {TRITON_DIR}")
        
        # Build Triton if needed
        triton_install_dir = TRITON_BUILD_DIR / "install"
        if args.force_rebuild or not triton_install_dir.exists():
            build_triton()
        else:
            print(f"Triton already built at {triton_install_dir}")
        
        # Build BScanner
        build_bscanner()
        
        print("\nBuild completed successfully!")
        exe_name = "bscanner.exe" if get_platform() == "windows" else "bscanner"
        print(f"Executable available at: {BUILD_DIR / exe_name}")
        
    except Exception as e:
        print(f"Build failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
