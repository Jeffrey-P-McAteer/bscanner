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

def main(args=sys.argv):
  subprocess.run([
    'uv', 'run', 'build.py',
  ], cwd=REPO_DIR, check=True)

  example_name = args[1]
  print(f'Compiling and running {example_name}')

  full_example_filepath = None
  for dirent in os.listdir(REPO_DIR / 'example-programs'):
    if example_name in dirent:
      full_example_filepath = str(REPO_DIR / 'example-programs' / dirent)

  test_binary_path = str(BUILD_DIR / example_name)
  cmd = [
    'gcc',
      '-o', test_binary_path,
      '-g', '-march=x86-64',
      full_example_filepath
  ]
  print(f'> {" ".join(cmd)}')
  subprocess.run(cmd, cwd=REPO_DIR, check=True)

  cmd = [
    str(BUILD_DIR / 'bscanner'),
    test_binary_path,
    '-vvv',
    '-o', 'json',
    '--args', *args[1:]
  ]
  print(f'> {" ".join(cmd)}')
  subprocess.run(cmd, cwd=REPO_DIR, check=True)


if __name__ == '__main__':
  main()
