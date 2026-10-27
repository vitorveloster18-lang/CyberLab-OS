# WSL2 & Ghidra / REA Integration Notes

- **Hopper** is proprietary macOS/Linux software and is never bundled with CyberLab OS or REA.
- **Ghidra** (`Apache-2.0`) is an external installation; headless Ghidra operations orchestrated through REA have known limitations on native Windows paths — always execute headless analysis inside the Linux ext4 filesystem of WSL2.
