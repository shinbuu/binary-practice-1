# Software Obfuscation Techniques – Report

## Objective

The primary objective of this work was to understand and apply code obfuscation techniques that make source code harder to read or analyze in order to protect logic from reverse engineering and unauthorized access or tampering.

---

## Introduction to Software Obfuscation

Software obfuscation is a technique used to modify a program so that it becomes harder for a human or automated system to understand its logic or behavior. This can be applied at various levels, including:

---

## Why Obfuscate?

- **Protect intellectual property**: Obfuscation is often part of a broader digital rights management (DRM) or copy protection strategy.
- **Hinder reverse engineering**: Slow down adversaries from analyzing or modifying the code.
- **Malware evasion**: Avoid detection and analysis by AV tools or researchers.
- **Performance optimizations**: e.g., minification in JavaScript.

---

## Categories of Obfuscation Techniques

Obfuscation techniques vary in complexity and performance impact. Choosing a suitable method depends on the goal (e.g., human analyst vs. automated tool). Categories include:

- **Control Flow Flattening**: Rewriting the logical flow to make the execution path unclear.
- **Self-Modifying Code**: The code modifies itself during execution.
- **Packers**: Execute parts of code in stages, decrypting each segment dynamically.
- **Droppers**: Download and run payload code at runtime.
- **Dead Code Insertion**: Add meaningless operations to reduce signal-to-noise ratio.
- **Virtual Machines (VMs)**: Create custom interpreters and instruction sets to hide the logic.
- **Anti-Debugging**: Detect debuggers and modify execution accordingly.

---

## Compilers and LLVM Architecture

To apply obfuscation at scale and across platforms, compilers like LLVM are used.
`git clone -b llvm-4.0 https://github.com/obfuscator-llvm/obfuscator` > `cd obfuscator` > `mkdir build > cd build` > `cmake -DCMAKE_BUILD_TYPE=Release ..` > `make -j4 clang` or `msbuild LLVM.sln /m:4` 
Open Developer Command Prompt for VS 2017  
Using LLVM for obfuscation allows language-agnostic transformation and better integration with existing tools.

---

## Obfuscation Tools

Two main approaches were explored:
```bash
`gcc ./source/obfuscated.c -o ./build/obfuscated`
`clang -c logic.c -o logic_obf -mllvm -sub -mllvm -fla -mllvm -bcf`
