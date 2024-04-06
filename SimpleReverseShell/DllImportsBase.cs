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

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern ulong htonl(ulong ipaddress);

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

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern int listen(IntPtr socket, int backlog);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    public static extern int bind(IntPtr socket, IntPtr name, int namelen);

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

    /// <summary>
    /// Dokumentation: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaprotocol_infoa
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAPROTOCOL_INFOA
    {
      int dwServiceFlags1;
      int dwServiceFlags2;
      int dwServiceFlags3;
      int dwServiceFlags4;
      int dwProviderFlags;
      Guid ProviderId;
      int dwCatalogEntryId;
      WSAPROTOCOLCHAIN ProtocolChain;
      int iVersion;
      int iAddressFamily;
      int iMaxSockAddr;
      int iMinSockAddr;
      int iSocketType;
      int iProtocol;
      int iProtocolMaxOffset;
      int iNetworkByteOrder;
      int iSecurityScheme;
      int dwMessageSize;
      int dwProviderReserved;
      char[] szProtocol;
    }

    /// <summary>
    /// Dokumentation: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaprotocolchain
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAPROTOCOLCHAIN
    {
      int ChainLen;
      int ChainEntries;
    }

    /// <summary>
    /// Dokumentation: https://learn.microsoft.com/de-de/windows/win32/api/winsock2/nf-winsock2-socket
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SOCKET
    {
      int af;
      int type;
      int protocol;
    }

    /// <summary>
    /// Dokumentation zu diesem Struct: https://learn.microsoft.com/de-de/windows/win32/winsock/sockaddr-2
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SockAddr_In
    {
      internal short s_family;
      internal ushort s_port;
      internal In_Addr s_addr;
      [MarshalAsAttribute(UnmanagedType.ByValTStr, SizeConst = 8)]
      internal string sin_zero;
    }

    /// <summary>
    /// Repräsentiert eine IPv4 Adresse.
    /// Dokumentation hierzu: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct In_Addr
    {
      public S_un_b S_un_b;

      public S_un_w S_un_w;

      public ulong S_addr;
    }

    [StructLayoutAttribute(LayoutKind.Sequential)]
    public struct S_un_b
    {
      /// u_char->unsigned char
      public byte s_b1;

      /// u_char->unsigned char
      public byte s_b2;

      /// u_char->unsigned char
      public byte s_b3;

      /// u_char->unsigned char
      public byte s_b4;
    }

    [StructLayoutAttribute(LayoutKind.Sequential)]
    public struct S_un_w
    {
      /// u_short->unsigned short
      public ushort s_w1;

      /// u_short->unsigned short
      public ushort s_w2;
    }

    /// <summary>
    /// Dokumentation zu diesem Struct: https://learn.microsoft.com/de-de/windows/win32/winsock/sockaddr-2
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct SockAddr
    {
      internal ushort sa_family;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
      internal string sa_data;
    }

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

    #endregion


    #region Test
    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
    public struct sockaddr_in
    {

      /// short
      public short sin_family;

      /// u_short->unsigned short
      public ushort sin_port;

      /// in_addr
      public in_addr sin_addr;

      /// char[8]
      [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 8)]
      public string sin_zero;
    }

    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct in_addr
    {
      public uint S_addr;
    }

    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
    public struct Anonymous_cf7219a7_561f_4650_8ae4_fbd5695fe221
    {

      /// Anonymous_8ee52dbc_a992_4853_a328_103fc9181176
      [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
      public Anonymous_8ee52dbc_a992_4853_a328_103fc9181176 S_un_b;

      /// Anonymous_63fe3feb_0017_41da_8c7f_24da3f99f4a8
      [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
      public Anonymous_63fe3feb_0017_41da_8c7f_24da3f99f4a8 S_un_w;

      /// u_long->unsigned int
      [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
      public long S_addr;
    }

    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct Anonymous_8ee52dbc_a992_4853_a328_103fc9181176
    {

      /// u_char->unsigned char
      public byte s_b1;

      /// u_char->unsigned char
      public byte s_b2;

      /// u_char->unsigned char
      public byte s_b3;

      /// u_char->unsigned char
      public byte s_b4;
    }

    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct Anonymous_63fe3feb_0017_41da_8c7f_24da3f99f4a8
    {

      /// u_short->unsigned short
      public ushort s_w1;

      /// u_short->unsigned short
      public ushort s_w2;
    }


    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
    public struct sockaddr
    {

      /// u_short->unsigned short
      public ushort sa_family;

      /// char[14]
      [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 14)]
      public string sa_data;
    }
    #endregion

    protected uint ConvertFromIPAddress(IPAddress ipAddress)
    {
      var bytes = ipAddress.GetAddressBytes();

      if (BitConverter.IsLittleEndian)
      {
        Array.Reverse(bytes);
      }

      return BitConverter.ToUInt32(bytes);
    }
  }
}
