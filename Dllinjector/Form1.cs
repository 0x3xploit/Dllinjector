using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Dllinjector
{
    public partial class Form1 : Form
    {
        // P/Invoke declarations
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport("kernel32.dll")]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct MODULEENTRY32
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        // Constants
        const uint PROCESS_CREATE_THREAD = 0x0002;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint PROCESS_VM_OPERATION = 0x0008;
        const uint PROCESS_VM_WRITE = 0x0020;
        const uint PROCESS_VM_READ = 0x0010;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint MEM_RELEASE = 0x8000;
        const uint PAGE_READWRITE = 4;
        const uint TH32CS_SNAPMODULE = 0x00000008;
        const uint TH32CS_SNAPMODULE32 = 0x00000010;

        private ListBox lstProcesses;
        private ListBox lstModules;
        private TextBox txtDllPath;
        private Button btnBrowse;
        private Button btnInject;
        private Button btnEject;
        private Button btnRefresh;
        private Button btnRefreshModules;
        private TextBox txtLog;
        private Label lblProcesses;
        private Label lblModules;
        private Label lblDllPath;
        private CheckBox chkAutoRefresh;
        private Timer refreshTimer;
        private Label lblArchitecture;
        private Label lblStatus;
        private Panel panelHeader;
        private Label lblTitle;
        private ProgressBar progressBar;

        public Form1()
        {
            InitializeComponent();
            InitializeCustomComponents();
            LoadProcesses();
        }

        private void InitializeCustomComponents()
        {
            // Form settings
            this.Text = "DLL Injector Pro";
            this.Size = new System.Drawing.Size(1000, 700);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.BackColor = ColorTranslator.FromHtml("#0a0e27");

            // Header Panel
            panelHeader = new Panel
            {
                Location = new Point(0, 0),
                Size = new Size(1000, 80),
                BackColor = ColorTranslator.FromHtml("#1a1f3a")
            };
            panelHeader.Paint += PanelHeader_Paint;

            // Title
            lblTitle = new Label
            {
                Text = "⚡ DLL INJECTOR PRO",
                Location = new Point(20, 15),
                AutoSize = false,
                Size = new Size(500, 50),
                Font = new Font("Consolas", 24F, FontStyle.Bold),
                ForeColor = ColorTranslator.FromHtml("#00ff41")
            };

            // Status Label
            lblStatus = new Label
            {
                Text = "● READY",
                Location = new Point(850, 30),
                AutoSize = true,
                Font = new Font("Consolas", 11F, FontStyle.Bold),
                ForeColor = ColorTranslator.FromHtml("#00ff41")
            };

            // Process list label
            lblProcesses = new Label
            {
                Text = "► RUNNING PROCESSES",
                Location = new Point(20, 100),
                AutoSize = true,
                Font = new Font("Consolas", 11F, FontStyle.Bold),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                BackColor = Color.Transparent
            };

            // Process list
            lstProcesses = new ListBox
            {
                Location = new Point(20, 130),
                Size = new Size(460, 200),
                Font = new Font("Consolas", 9F),
                BackColor = ColorTranslator.FromHtml("#1a1f3a"),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                BorderStyle = BorderStyle.FixedSingle
            };
            lstProcesses.SelectedIndexChanged += LstProcesses_SelectedIndexChanged;

            // Modules list label
            lblModules = new Label
            {
                Text = "► LOADED MODULES",
                Location = new Point(500, 100),
                AutoSize = true,
                Font = new Font("Consolas", 11F, FontStyle.Bold),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                BackColor = Color.Transparent
            };

            // Modules list
            lstModules = new ListBox
            {
                Location = new Point(500, 130),
                Size = new Size(460, 200),
                Font = new Font("Consolas", 9F),
                BackColor = ColorTranslator.FromHtml("#1a1f3a"),
                ForeColor = ColorTranslator.FromHtml("#00d4ff"),
                BorderStyle = BorderStyle.FixedSingle
            };

            // Auto-refresh checkbox
            chkAutoRefresh = new CheckBox
            {
                Text = "AUTO-REFRESH",
                Location = new Point(20, 340),
                AutoSize = true,
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                BackColor = Color.Transparent
            };
            chkAutoRefresh.CheckedChanged += ChkAutoRefresh_CheckedChanged;

            // Refresh processes button
            btnRefresh = new Button
            {
                Text = "⟳ REFRESH PROCESSES",
                Location = new Point(350, 335),
                Size = new Size(130, 30),
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                BackColor = ColorTranslator.FromHtml("#1a1f3a"),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                FlatStyle = FlatStyle.Flat
            };
            btnRefresh.FlatAppearance.BorderColor = ColorTranslator.FromHtml("#00ff41");
            btnRefresh.Click += BtnRefresh_Click;

            // Refresh modules button
            btnRefreshModules = new Button
            {
                Text = "⟳ REFRESH MODULES",
                Location = new Point(830, 335),
                Size = new Size(130, 30),
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                BackColor = ColorTranslator.FromHtml("#1a1f3a"),
                ForeColor = ColorTranslator.FromHtml("#00d4ff"),
                FlatStyle = FlatStyle.Flat
            };
            btnRefreshModules.FlatAppearance.BorderColor = ColorTranslator.FromHtml("#00d4ff");
            btnRefreshModules.Click += BtnRefreshModules_Click;

            // Architecture label
            lblArchitecture = new Label
            {
                Text = "[" + (Environment.Is64BitProcess ? "64-BIT MODE" : "32-BIT MODE") + "]",
                Location = new Point(170, 342),
                AutoSize = true,
                ForeColor = ColorTranslator.FromHtml("#ff00ff"),
                Font = new Font("Consolas", 9F, FontStyle.Bold),
                BackColor = Color.Transparent
            };

            // DLL Path label
            lblDllPath = new Label
            {
                Text = "► DLL FILE PATH",
                Location = new Point(20, 390),
                AutoSize = true,
                Font = new Font("Consolas", 11F, FontStyle.Bold),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                BackColor = Color.Transparent
            };

            // DLL Path textbox
            txtDllPath = new TextBox
            {
                Location = new Point(20, 420),
                Size = new Size(850, 30),
                Font = new Font("Consolas", 10F),
                BackColor = ColorTranslator.FromHtml("#1a1f3a"),
                ForeColor = ColorTranslator.FromHtml("#ffffff"),
                BorderStyle = BorderStyle.FixedSingle
            };

            // Browse button
            btnBrowse = new Button
            {
                Text = "📁",
                Location = new Point(880, 418),
                Size = new Size(80, 30),
                Font = new Font("Segoe UI", 14F),
                BackColor = ColorTranslator.FromHtml("#1a1f3a"),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                FlatStyle = FlatStyle.Flat
            };
            btnBrowse.FlatAppearance.BorderColor = ColorTranslator.FromHtml("#00ff41");
            btnBrowse.Click += BtnBrowse_Click;

            // Progress bar
            progressBar = new ProgressBar
            {
                Location = new Point(20, 465),
                Size = new Size(940, 10),
                Style = ProgressBarStyle.Continuous,
                Visible = false
            };

            // Inject button
            btnInject = new Button
            {
                Text = "⚡ INJECT DLL",
                Location = new Point(20, 490),
                Size = new Size(465, 45),
                Font = new Font("Consolas", 13F, FontStyle.Bold),
                BackColor = ColorTranslator.FromHtml("#00ff41"),
                ForeColor = ColorTranslator.FromHtml("#0a0e27"),
                FlatStyle = FlatStyle.Flat
            };
            btnInject.FlatAppearance.BorderSize = 0;
            btnInject.Click += BtnInject_Click;

            // Eject button
            btnEject = new Button
            {
                Text = "🔌 EJECT DLL",
                Location = new Point(495, 490),
                Size = new Size(465, 45),
                Font = new Font("Consolas", 13F, FontStyle.Bold),
                BackColor = ColorTranslator.FromHtml("#ff4444"),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnEject.FlatAppearance.BorderSize = 0;
            btnEject.Click += BtnEject_Click;

            // Log textbox
            txtLog = new TextBox
            {
                Location = new Point(20, 550),
                Size = new Size(940, 100),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = ColorTranslator.FromHtml("#0a0a0a"),
                ForeColor = ColorTranslator.FromHtml("#00ff41"),
                Font = new Font("Consolas", 9F),
                BorderStyle = BorderStyle.FixedSingle
            };

            // Timer for auto-refresh
            refreshTimer = new Timer();
            refreshTimer.Interval = 5000;
            refreshTimer.Tick += RefreshTimer_Tick;

            // Add controls
            this.Controls.Add(panelHeader);
            panelHeader.Controls.Add(lblTitle);
            panelHeader.Controls.Add(lblStatus);
            this.Controls.Add(lblProcesses);
            this.Controls.Add(lstProcesses);
            this.Controls.Add(lblModules);
            this.Controls.Add(lstModules);
            this.Controls.Add(chkAutoRefresh);
            this.Controls.Add(btnRefresh);
            this.Controls.Add(btnRefreshModules);
            this.Controls.Add(lblArchitecture);
            this.Controls.Add(lblDllPath);
            this.Controls.Add(txtDllPath);
            this.Controls.Add(btnBrowse);
            this.Controls.Add(progressBar);
            this.Controls.Add(btnInject);
            this.Controls.Add(btnEject);
            this.Controls.Add(txtLog);

            Log("╔════════════════════════════════════════════════════════════╗");
            Log("║           DLL INJECTOR PRO - SYSTEM INITIALIZED           ║");
            Log("╚════════════════════════════════════════════════════════════╝");
            Log($"[SYSTEM] Running in {(Environment.Is64BitProcess ? "64-BIT" : "32-BIT")} mode");
            Log($"[SYSTEM] OS: {Environment.OSVersion}");
        }

        private void PanelHeader_Paint(object sender, PaintEventArgs e)
        {
            LinearGradientBrush brush = new LinearGradientBrush(
                panelHeader.ClientRectangle,
                ColorTranslator.FromHtml("#1a1f3a"),
                ColorTranslator.FromHtml("#0a0e27"),
                90F);
            e.Graphics.FillRectangle(brush, panelHeader.ClientRectangle);
        }

        private void LoadProcesses()
        {
            lstProcesses.Items.Clear();
            var processes = Process.GetProcesses()
                .Where(p => !string.IsNullOrEmpty(p.MainWindowTitle) || p.ProcessName.Length > 0)
                .OrderBy(p => p.ProcessName)
                .ToList();

            foreach (var process in processes)
            {
                try
                {
                    string arch = GetProcessArchitecture(process);
                    string display = $"{process.ProcessName.PadRight(30)} │ PID: {process.Id.ToString().PadRight(6)} │ {arch}";
                    lstProcesses.Items.Add(display);
                }
                catch { }
            }

            Log($"[SCAN] Loaded {lstProcesses.Items.Count} processes");
        }

        private void LoadModules(int processId)
        {
            lstModules.Items.Clear();

            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)processId);
            if (hSnapshot == IntPtr.Zero || hSnapshot == new IntPtr(-1))
            {
                Log("[ERROR] Failed to create module snapshot");
                return;
            }

            MODULEENTRY32 me32 = new MODULEENTRY32();
            me32.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

            if (Module32First(hSnapshot, ref me32))
            {
                do
                {
                    string display = $"{me32.szModule.PadRight(35)} │ Base: 0x{me32.modBaseAddr.ToString("X").PadLeft(12, '0')}";
                    lstModules.Items.Add(display);
                } while (Module32Next(hSnapshot, ref me32));
            }

            CloseHandle(hSnapshot);
            Log($"[SCAN] Found {lstModules.Items.Count} loaded modules");
        }

        private string GetProcessArchitecture(Process process)
        {
            try
            {
                IntPtr handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, process.Id);
                if (handle == IntPtr.Zero)
                    return "???";

                bool isWow64;
                IsWow64Process(handle, out isWow64);
                CloseHandle(handle);

                if (Environment.Is64BitOperatingSystem)
                {
                    return isWow64 ? "32-BIT" : "64-BIT";
                }
                return "32-BIT";
            }
            catch
            {
                return "???";
            }
        }

        private void UpdateStatus(string status, string color)
        {
            lblStatus.Text = $"● {status}";
            lblStatus.ForeColor = ColorTranslator.FromHtml(color);
        }

        private void BtnBrowse_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "DLL Files (*.dll)|*.dll|All Files (*.*)|*.*";
                ofd.Title = "Select DLL to Inject";

                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    txtDllPath.Text = ofd.FileName;
                    Log($"[SELECT] {Path.GetFileName(ofd.FileName)}");
                }
            }
        }

        private void BtnRefresh_Click(object sender, EventArgs e)
        {
            UpdateStatus("SCANNING", "#ffaa00");
            LoadProcesses();
            UpdateStatus("READY", "#00ff41");
        }

        private void BtnRefreshModules_Click(object sender, EventArgs e)
        {
            if (lstProcesses.SelectedItem == null)
            {
                MessageBox.Show("Please select a process first!", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string selected = lstProcesses.SelectedItem.ToString();
            int pid = ExtractPID(selected);

            UpdateStatus("SCANNING", "#ffaa00");
            LoadModules(pid);
            UpdateStatus("READY", "#00ff41");
        }

        private void RefreshTimer_Tick(object sender, EventArgs e)
        {
            LoadProcesses();
        }

        private void ChkAutoRefresh_CheckedChanged(object sender, EventArgs e)
        {
            refreshTimer.Enabled = chkAutoRefresh.Checked;
            Log(chkAutoRefresh.Checked ? "[AUTO-REFRESH] Enabled" : "[AUTO-REFRESH] Disabled");
        }

        private void LstProcesses_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (lstProcesses.SelectedItem != null)
            {
                string selected = lstProcesses.SelectedItem.ToString();
                int pid = ExtractPID(selected);
                Log($"[SELECT] Process selected - PID: {pid}");
                LoadModules(pid);
            }
        }

        private async void BtnInject_Click(object sender, EventArgs e)
        {
            if (lstProcesses.SelectedItem == null)
            {
                MessageBox.Show("Please select a process!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (string.IsNullOrEmpty(txtDllPath.Text) || !File.Exists(txtDllPath.Text))
            {
                MessageBox.Show("Please select a valid DLL file!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string selected = lstProcesses.SelectedItem.ToString();
            int pid = ExtractPID(selected);

            if (pid == 0)
            {
                Log("[ERROR] Could not extract process ID");
                return;
            }

            UpdateStatus("INJECTING", "#ffaa00");
            progressBar.Visible = true;
            progressBar.Style = ProgressBarStyle.Marquee;

            Log("╔════════════════════════════════════════════════════════════╗");
            Log($"[INJECT] Starting injection into PID: {pid}");

            await Task.Run(() => InjectDLL(pid, txtDllPath.Text));

            progressBar.Visible = false;
        }

        private async void BtnEject_Click(object sender, EventArgs e)
        {
            if (lstProcesses.SelectedItem == null)
            {
                MessageBox.Show("Please select a process!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (lstModules.SelectedItem == null)
            {
                MessageBox.Show("Please select a module to eject!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string selected = lstProcesses.SelectedItem.ToString();
            int pid = ExtractPID(selected);

            string moduleSelected = lstModules.SelectedItem.ToString();
            string moduleName = moduleSelected.Split('│')[0].Trim();

            UpdateStatus("EJECTING", "#ff4444");
            progressBar.Visible = true;
            progressBar.Style = ProgressBarStyle.Marquee;

            Log("╔════════════════════════════════════════════════════════════╗");
            Log($"[EJECT] Attempting to eject: {moduleName}");

            await Task.Run(() => EjectDLL(pid, moduleName));

            progressBar.Visible = false;
        }

        private int ExtractPID(string processLine)
        {
            try
            {
                int pidIndex = processLine.IndexOf("PID:");
                if (pidIndex == -1) return 0;

                string pidPart = processLine.Substring(pidIndex + 4).Trim();
                string pidStr = pidPart.Split('│')[0].Trim();
                return int.Parse(pidStr);
            }
            catch
            {
                return 0;
            }
        }

        private bool InjectDLL(int processId, string dllPath)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr allocMemAddress = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;

            try
            {
                hProcess = OpenProcess(
                    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                    false, processId);

                if (hProcess == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log($"[ERROR] Failed to open process. Code: {Marshal.GetLastWin32Error()}");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log("[SUCCESS] Process opened");
                });

                bool targetIs32Bit;
                IsWow64Process(hProcess, out targetIs32Bit);
                bool injectorIs32Bit = !Environment.Is64BitProcess;

                if (Environment.Is64BitOperatingSystem && targetIs32Bit != injectorIs32Bit)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log("[ERROR] Architecture mismatch!");
                        Log($"[INFO] Injector: {(injectorIs32Bit ? "32" : "64")}-bit | Target: {(targetIs32Bit ? "32" : "64")}-bit");
                        UpdateStatus("FAILED", "#ff4444");
                        MessageBox.Show("Architecture mismatch!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    });
                    return false;
                }

                byte[] dllBytes = Encoding.Unicode.GetBytes(dllPath);
                allocMemAddress = VirtualAllocEx(
                    hProcess, IntPtr.Zero, (uint)dllBytes.Length,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (allocMemAddress == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log($"[ERROR] Memory allocation failed. Code: {Marshal.GetLastWin32Error()}");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log($"[SUCCESS] Memory allocated at: 0x{allocMemAddress.ToString("X")}");
                });

                int bytesWritten;
                if (!WriteProcessMemory(hProcess, allocMemAddress, dllBytes, (uint)dllBytes.Length, out bytesWritten))
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log($"[ERROR] Write failed. Code: {Marshal.GetLastWin32Error()}");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log($"[SUCCESS] Written {bytesWritten} bytes");
                });

                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
                if (loadLibraryAddr == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log("[ERROR] Failed to get LoadLibraryW");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log($"[SUCCESS] LoadLibraryW at: 0x{loadLibraryAddr.ToString("X")}");
                });

                hThread = CreateRemoteThread(
                    hProcess, IntPtr.Zero, 0, loadLibraryAddr,
                    allocMemAddress, 0, IntPtr.Zero);

                if (hThread == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log($"[ERROR] Thread creation failed. Code: {Marshal.GetLastWin32Error()}");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log("[SUCCESS] Remote thread created");
                });

                WaitForSingleObject(hThread, 5000);

                this.Invoke((MethodInvoker)delegate {
                    Log("[SUCCESS] Thread execution completed");
                    Log("╚════════════════════════════════════════════════════════════╝");
                    Log("[INJECT] ✓ INJECTION SUCCESSFUL!");
                    UpdateStatus("INJECTED", "#00ff41");
                    MessageBox.Show("DLL injected successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    LoadModules(processId);
                });

                return true;
            }
            catch (Exception ex)
            {
                this.Invoke((MethodInvoker)delegate {
                    Log($"[EXCEPTION] {ex.Message}");
                    UpdateStatus("FAILED", "#ff4444");
                });
                return false;
            }
            finally
            {
                if (hThread != IntPtr.Zero)
                    CloseHandle(hThread);
                if (hProcess != IntPtr.Zero)
                    CloseHandle(hProcess);
            }
        }

        private bool EjectDLL(int processId, string moduleName)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;

            try
            {
                hProcess = OpenProcess(
                    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                    false, processId);

                if (hProcess == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log($"[ERROR] Failed to open process. Code: {Marshal.GetLastWin32Error()}");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log("[SUCCESS] Process opened");
                });

                IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)processId);
                if (hSnapshot == IntPtr.Zero || hSnapshot == new IntPtr(-1))
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log("[ERROR] Failed to create module snapshot");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                MODULEENTRY32 me32 = new MODULEENTRY32();
                me32.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));
                IntPtr moduleHandle = IntPtr.Zero;

                if (Module32First(hSnapshot, ref me32))
                {
                    do
                    {
                        if (me32.szModule.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                        {
                            moduleHandle = me32.hModule;
                            break;
                        }
                    } while (Module32Next(hSnapshot, ref me32));
                }

                CloseHandle(hSnapshot);

                if (moduleHandle == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log("[ERROR] Module not found in process");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log($"[SUCCESS] Module found at: 0x{moduleHandle.ToString("X")}");
                });

                IntPtr freeLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");
                if (freeLibraryAddr == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log("[ERROR] Failed to get FreeLibrary address");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log($"[SUCCESS] FreeLibrary at: 0x{freeLibraryAddr.ToString("X")}");
                });

                hThread = CreateRemoteThread(
                    hProcess, IntPtr.Zero, 0, freeLibraryAddr,
                    moduleHandle, 0, IntPtr.Zero);

                if (hThread == IntPtr.Zero)
                {
                    this.Invoke((MethodInvoker)delegate {
                        Log($"[ERROR] Failed to create remote thread. Code: {Marshal.GetLastWin32Error()}");
                        UpdateStatus("FAILED", "#ff4444");
                    });
                    return false;
                }

                this.Invoke((MethodInvoker)delegate {
                    Log("[SUCCESS] Remote thread created");
                });

                WaitForSingleObject(hThread, 5000);

                this.Invoke((MethodInvoker)delegate {
                    Log("[SUCCESS] Thread execution completed");
                    Log("╚════════════════════════════════════════════════════════════╝");
                    Log("[EJECT] ✓ DLL EJECTED SUCCESSFULLY!");
                    UpdateStatus("EJECTED", "#00ff41");
                    MessageBox.Show("DLL ejected successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    LoadModules(processId);
                });

                return true;
            }
            catch (Exception ex)
            {
                this.Invoke((MethodInvoker)delegate {
                    Log($"[EXCEPTION] {ex.Message}");
                    UpdateStatus("FAILED", "#ff4444");
                });
                return false;
            }
            finally
            {
                if (hThread != IntPtr.Zero)
                    CloseHandle(hThread);
                if (hProcess != IntPtr.Zero)
                    CloseHandle(hProcess);
            }
        }

        private void Log(string message)
        {
            if (txtLog.InvokeRequired)
            {
                txtLog.Invoke((MethodInvoker)delegate {
                    string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                    txtLog.AppendText($"[{timestamp}] {message}\r\n");
                });
            }
            else
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                txtLog.AppendText($"[{timestamp}] {message}\r\n");
            }
        }
    }
}