using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography
{
    public interface ITuringCipher : IDisposable
    {
        void SetKey(byte[] key);
        void SetIV(byte[] iv);
        IEnumerable<ArraySegment<byte>> GetNextRounds();
    }
}
