# DllInjector

### A simple, reliable DLL injector for Windows with a dark-themed UI. It supports injecting and ejecting DLLs into both 32-bit and 64-bit processes, can target any running process for injection, and — after injection — lists all modules loaded in the target process along with each module's base address. The tool also provides real-time process monitoring and detailed timestamped logging.
---
<img width="1005" height="708" alt="Screenshot 2025-11-12 153159" src="https://github.com/user-attachments/assets/4782ad63-e9bc-45c6-84e0-9aab80e9e32f" />





## Features

- Inject DLLs into 32-bit and 64-bit processes
- Eject loaded DLLs from processes
- View all loaded modules in a process
- Real-time process monitoring with auto-refresh
- Architecture detection (32-bit / 64-bit)
- Detailed logging with timestamps
- Dark themed UI

---

## Requirements

- Windows 10 or Windows 11
- .NET Framework 4.7.2 or higher
- Administrator privileges

---

## Installation

1. Download the latest release.
2. Extract the files.
3. Run `Dllinjector.exe` as **Administrator**.

---

## Building from Source

### Prerequisites

- Visual Studio 2019 or later
- .NET Framework 4.7.2 SDK

### Build Instructions

```bash
git clone https://github.com/yourusername/dll-injector-pro.git
cd dll-injector-pro
```

1. Open `Dllinjector.sln` in Visual Studio.
2. Select your target platform:
   - **x86** for 32-bit processes
   - **x64** for 64-bit processes
3. Build the solution (Ctrl+Shift+B).

The executable will be available in `bin/Debug` or `bin/Release` depending on your configuration.

---

## Usage

### Injecting a DLL

1. Launch the application as **Administrator**.
2. Select a target process from the process list.
3. Click **Browse** and select your DLL file.
4. Click **⚡ INJECT DLL**.
5. Check the log output for confirmation.

### Ejecting a DLL

1. Select a process from the process list.
2. The loaded modules will appear in the modules panel.
3. Select the module you want to eject.
4. Click **🔌 EJECT DLL**.
5. Check the log output for confirmation.

---

## Important Notes

- **Architecture compatibility:** The injector architecture must match the target process.
  - 32-bit injector → 32-bit processes only
  - 64-bit injector → 64-bit processes only
  - You cannot inject across architectures. Build both versions if you need to target both.

- **Administrator rights:** The tool requires administrator privileges to:
  - Open process handles
  - Allocate memory in other processes
  - Create remote threads

Always run the injector as Administrator or injection will fail.

---

## How It Works

The injector uses `CreateRemoteThread` with `LoadLibrary` to load the DLL into the target process:

1. Open the target process with the required permissions.
2. Allocate memory in the target process.
3. Write the DLL path into the allocated memory.
4. Create a remote thread that calls `LoadLibrary` with the DLL path.
5. `DllMain` in the injected DLL executes.

For ejection:

1. Locate the module handle inside the target process.
2. Create a remote thread that calls `FreeLibrary` with the module handle.
3. The DLL is unloaded and cleaned up.

---

## Troubleshooting

- **"Failed to open process"**
  - Run the injector as Administrator.
  - The target process may use anti-debug or protection mechanisms.
  - Verify you have the required permissions.

- **"Architecture mismatch"**
  - Rebuild the injector for the target process architecture.
  - Use the x86 build for 32-bit processes and x64 build for 64-bit processes.

- **"Module not found"**
  - Make sure you selected the correct module; refresh the module list.
  - The module may have already been unloaded.

- **Injection succeeds but DLL doesn't work**
  - Confirm the DLL is compiled for the correct architecture.
  - Verify the DLL has no missing dependencies.
  - Review the DLL's `DllMain` implementation for errors.

---

## Security & Legal

This tool modifies other processes and requires elevated privileges. Use it only on systems and software you own or are explicitly authorized to test. Misuse may violate software licenses and local laws.

---
