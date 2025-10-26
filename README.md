# elfuscator

[![elfuscator-logo.png](https://i.postimg.cc/2SRL5yfs/elfuscator-logo.png)](https://postimg.cc/fJCR2wyC)

Elfuscator is a binary obfuscation toolkit for x86_64 ELF executables on Linux.

## Build

```
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage

Run `elfuscator` with one option at a time. You can run it multiple times on the same binary to apply different transformations in sequence.

```shell-session
$ ./elfuscator -h

Usage:
  ./elfuscator -s <path-to-elf>   Strip section headers
  ./elfuscator -p <path-to-elf>   Spoof section headers
  ./elfuscator -y <path-to-elf>   Shuffle dynamic symbols
  ./elfuscator -e <path-to-elf>   Switch endianness
  ./elfuscator -t <path-to-elf>   Disable tracers
  ./elfuscator -d <path-to-elf>   Disable core dumps
  ./elfuscator -c <path-to-elf>   Encrypt code segment
  ./elfuscator -h | --help        Show this help message
```

Supports 64-bit Linux **executables** only (static or dynamic, PIE or non-PIE). **Shared objects (.so) are not supported.**



 


