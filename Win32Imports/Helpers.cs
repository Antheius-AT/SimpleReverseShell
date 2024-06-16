using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Win32Imports.DllImportsBase;

namespace Win32Imports
{
  public static class Helpers
  {
    public static void InitializeWSA()
    {
      var wsa = new WSAData();
      WSAStartup((ushort)2.2, wsa);

      PrintLastError(nameof(WSAStartup), true);
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
  }
}
