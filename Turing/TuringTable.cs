using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography
{
    public class TuringTable : Turing
    {
        protected override ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV)
        {
            throw new NotImplementedException();
        }
    }
}
