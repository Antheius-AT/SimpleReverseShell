using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Win32Imports
{
  public class Serializer
  {
    private BinaryWriter bw;
    private BinaryReader br;

    public Serializer(FileStream fileStream)
    {
      bw = new BinaryWriter(fileStream);
      br = new BinaryReader(fileStream);
    }
    
    public void Serialize(IntPtr socket)
    {
      bw.BaseStream.Seek(0, SeekOrigin.Begin);
      bw.Write(socket.ToInt64());
    }

    public IntPtr Deserialize()
    {
      br.BaseStream.Seek(0, SeekOrigin.Begin);
      return new IntPtr(br.ReadInt64());
    }
  }
}
