
#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
import shutil
import urllib.request
import tarfile
import zipfile
import argparse
from pathlib import Path

REPO_DIR = Path(__file__).parent.absolute()
BUILD_DIR = REPO_DIR / "build"
TRITON_DIR = BUILD_DIR / "triton"
TRITON_BUILD_DIR = BUILD_DIR / "triton-build"

TRITON_VERSION = "1.0.0"
TRITON_URLS = {
    "linux": f"https://github.com/JonathanSalwan/Triton/archive/refs/tags/v{TRITON_VERSION}.tar.gz",
    "windows": f"https://github.com/JonathanSalwan/Triton/archive/refs/tags/v{TRITON_VERSION}.zip",
    "darwin": f"https://github.com/JonathanSalwan/Triton/archive/refs/tags/v{TRITON_VERSION}.tar.gz"
}

def get_platform():
    """Detect the current platform."""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    elif system == "darwin":
        return "darwin"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")

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

def download_triton():
    """Download Triton source code."""
    platform_name = get_platform()
    url = TRITON_URLS[platform_name]
    
    print(f"Downloading Triton {TRITON_VERSION} for {platform_name}...")
    
    BUILD_DIR.mkdir(exist_ok=True)
    
    if platform_name == "windows":
        archive_path = BUILD_DIR / f"triton-{TRITON_VERSION}.zip"
    else:
        archive_path = BUILD_DIR / f"triton-{TRITON_VERSION}.tar.gz"
    
    if not archive_path.exists():
        urllib.request.urlretrieve(url, archive_path)
        print(f"Downloaded to {archive_path}")
    else:
        print(f"Archive already exists: {archive_path}")
    
    # Extract archive
    if TRITON_DIR.exists():
        shutil.rmtree(TRITON_DIR)
    
    if platform_name == "windows":
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(BUILD_DIR)
        extracted_dir = BUILD_DIR / f"Triton-{TRITON_VERSION}"
    else:
        with tarfile.open(archive_path, 'r:gz') as tar_ref:
            tar_ref.extractall(BUILD_DIR)
        extracted_dir = BUILD_DIR / f"Triton-{TRITON_VERSION}"
    
    extracted_dir.rename(TRITON_DIR)
    print(f"Extracted Triton to {TRITON_DIR}")

def build_triton():
    """Build Triton library."""
    print("Building Triton...")
    
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
    platform_name = get_platform()
    if platform_name == "windows":
        cmake_cmd.extend(["-G", "Visual Studio 16 2019", "-A", "x64"])
    
    run_command(cmake_cmd, cwd=TRITON_BUILD_DIR)
    
    # Build Triton
    build_cmd = ["cmake", "--build", ".", "--config", "Release"]
    if platform_name != "windows":
        build_cmd.extend(["-j", str(os.cpu_count() or 4)])
    
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
    
    # Configure BScanner build
    cmake_cmd = [
        "cmake",
        str(REPO_DIR),
        f"-DTRITON_ROOT={triton_install_dir}",
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
        try:
            run_command(["where", "msbuild"], check=False)
        except:
            print("Warning: MSBuild not found. Please install Visual Studio or Build Tools for Visual Studio.")
    else:
        required_tools.extend(["make", "gcc"])
    
    missing_tools = []
    for tool in required_tools:
        try:
            if platform_name == "windows":
                run_command(["where", tool], check=False)
            else:
                run_command(["which", tool], check=False)
        except:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"Error: Missing required tools: {', '.join(missing_tools)}")
        return False
    
    print("All required build tools are available.")
    return True

def main():
    parser = argparse.ArgumentParser(description="Build BScanner with automatic Triton dependency management")
    parser.add_argument("command", nargs="?", default="build", choices=["build", "clean"],
                       help="Command to execute (default: build)")
    parser.add_argument("--force-download", action="store_true",
                       help="Force re-download of Triton even if it exists")
    parser.add_argument("--force-rebuild", action="store_true",
                       help="Force rebuild of Triton even if it's already built")
    
    args = parser.parse_args()
    
    if args.command == "clean":
        clean()
        return
    
    if not check_dependencies():
        sys.exit(1)
    
    try:
        # Download Triton if needed
        if args.force_download or not TRITON_DIR.exists():
            download_triton()
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
