# elfuscator

[![elfuscator-logo.png](https://i.postimg.cc/vTsdnvDs/elfuscator-logo.png)](https://postimg.cc/N9pVqm1J)

Elfuscator is an anti-reversing and obfuscation toolkit for x86_64 ELF binaries on Linux.

## Build

```shell
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage

Run `elfuscator` with one option at a time. You can run it multiple times on the same binary to apply different transformations in sequence.

```shell
./elfuscator -h

Usage:
  ./elfuscator -s <path-to-elf>   Strip section header table
  ./elfuscator -p <path-to-elf>   Spoof section header table
  ./elfuscator -y <path-to-elf>   Shuffle dynamic symbol names
  ./elfuscator -e <path-to-elf>   Switch endianness (ELFDATA2LSB <-> ELFDATA2MSB)
  ./elfuscator -r <path-to-elf>   Randomize padding bytes
  ./elfuscator -d <path-to-elf>   Disable core dumps
  ./elfuscator -c <path-to-elf>   Encrypt code segment
  ./elfuscator -h | --help        Show this help message
```
