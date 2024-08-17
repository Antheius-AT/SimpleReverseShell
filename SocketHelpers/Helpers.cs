using System.Runtime.InteropServices;

namespace SocketHelpers
{
  public class Helpers
  {
    #region Sockets
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
    #endregion

    #region HelperMethods
    public static void InitializeWSA()
    {
      var wsa = new WSAData();
      WSAStartup((ushort)2.2, wsa);

      PrintLastError(nameof(WSAStartup), true);
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
    #endregion
  }
}