using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal; 



//  Made By Inputt Star my repo please!  https://github.com/inputtdevv/CriticalProcessKiller/
namespace CProcKiller
{
    class Program
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        const uint ProcAllAccess = 0x1F0FFF;
        const uint TokenAdjustPrivilages = 0x0020;
        const uint TokenQuery = 0x0008;
        const uint SePrivilageEnabled = 0x00000002;
        const string DebugName = "SeDebugPrivilege";

        struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        const int BreakOnTermination = 0x1D;

        static void Main(string[] args)
        {
            if (!IsRunningAsAdmin())
            {
                RelaunchAsAdmin();
                return;
            }

            EnableDebugPrivilege();

            int currentPid = Process.GetCurrentProcess().Id;

            ConsoleColor[] gradientColors = {
                ConsoleColor.DarkGreen, ConsoleColor.Green, ConsoleColor.DarkGreen,
                ConsoleColor.Green, ConsoleColor.DarkGreen, ConsoleColor.Green
            };

            string pidText = $"[+] PID : {currentPid}";
            for (int i = 0; i < pidText.Length; i++)
            {
                Console.ForegroundColor = gradientColors[i % gradientColors.Length];
                Console.Write(pidText[i]);
            }
            Console.ResetColor();
            Console.WriteLine("\Critical Process Killer - https://github.com/inputtdevv/CriticalProcessKiller/edit/main/Killer.cs Created by inputt");

            Console.Write("[");
            for (int i = 0; i < 1; i++)
            {
                Console.ForegroundColor = gradientColors[i % gradientColors.Length];
                Console.Write("-");
            }
            Console.ForegroundColor = gradientColors[1 % gradientColors.Length];
            Console.Write("] ");

            string promptText = "Enter PID: ";
            for (int i = 0; i < promptText.Length; i++)
            {
                Console.ForegroundColor = gradientColors[(i * 2) % gradientColors.Length];
                Console.Write(promptText[i]);
            }

            Console.ResetColor();
            Console.Write(" ");

            string input = Console.ReadLine();
            if (int.TryParse(input, out int pid) && pid != currentPid)
            {
                try
                {
                    Process process = Process.GetProcessById(pid);
                    string processName = process.ProcessName.ToLowerInvariant();

                    bool targetIsCritical = false;
                    IntPtr hProcess = OpenProcess(ProcAllAccess, false, pid);
                    if (hProcess != IntPtr.Zero)
                    {
                        int criticalFlag = 0;
                        int result = NtSetInformationProcess(hProcess, BreakOnTermination, ref criticalFlag, 4);
                        if (result == 0)
                        {
                            targetIsCritical = (criticalFlag == 1);
                        }
                        CloseHandle(hProcess);
                    }

                    if (targetIsCritical)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"\n[!] '{processName}' is critical. Disabling critical flag to kill it.");
                        Console.ResetColor();

                        hProcess = OpenProcess(ProcAllAccess, false, pid);
                        if (hProcess != IntPtr.Zero)
                        {
                            int disableCritical = 0;
                            NtSetInformationProcess(hProcess, BreakOnTermination, ref disableCritical, 4);
                            CloseHandle(hProcess);
                        }
                    }

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("Confirm kill? (y/N): ");
                    Console.ResetColor();
                    if (Console.ReadLine().ToLower() != "y")
                    {
                        return;
                    }

                    process.Kill();
                    process.WaitForExit(5000);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n[+] Process '{process.ProcessName}' (PID: {pid}) terminated safley.");
                    if (targetIsCritical)
                    {
                        Console.WriteLine("[+] Critical flag disabled - no crash.");
                    }
                    Console.ResetColor();
                }
                catch (ArgumentException)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[!] Invalid PID: No process found with that PID.");
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\n[!] Error terminating process: {ex.Message}");
                    Console.ResetColor();
                }
            }
            else if (pid == currentPid)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!] Cannot terminate self.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!] Invalid input: Please enter a valid PID.");
                Console.ResetColor();
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        static void EnableDebugPrivilege()
        {
            IntPtr token;
            if (OpenProcessToken(Process.GetCurrentProcess().Handle, TokenAdjustPrivilages | TokenQuery, out token))
            {
                try
                {
                    LUID luid;
                    if (LookupPrivilegeValue(null, DebugName, out luid))
                    {
                        TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                        {
                            PrivilegeCount = 1,
                            Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SePrivilageEnabled }
                        };
                        AdjustTokenPrivileges(token, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
                    }
                }
                finally
                {
                    CloseHandle(token);
                }
            }
        }

        static bool IsRunningAsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void RelaunchAsAdmin()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                UseShellExecute = true,
                WorkingDirectory = Environment.CurrentDirectory,
                FileName = Process.GetCurrentProcess().MainModule.FileName,
                Verb = "runas"
            };
            try
            {
                Process.Start(startInfo);
            }
            catch (Exception)
            {
                Console.WriteLine("Failed to elevate privileges.");
            }
            Environment.Exit(0);
        }
    }
}
