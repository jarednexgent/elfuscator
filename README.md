# elfuscator

[![elfuscator-logo.png](https://i.postimg.cc/5trh9NYc/elfuscator-logo.png)](https://postimg.cc/XZwHQWkx)

Elfuscator is an anti-analysis tool for ELF files.

## Build

```shell
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage

Run elfuscator with one option at a time. You can run it multiple times on the same binary to apply different transformations in sequence.

```shell
./elfuscator -h

Usage:
  ./elfuscator -s <path-to-elf>   Remove section header table
  ./elfuscator -p <path-to-elf>   Insert spoofed section headers
  ./elfuscator -y <path-to-elf>   Shuffle dynamic symbol names
  ./elfuscator -e <path-to-elf>   Switch endianness (ELFDATA2LSB <-> ELFDATA2MSB)
  ./elfuscator -c <path-to-elf>   Add code segment cryptor stub
  ./elfuscator -h | --help        Show this help message
```
