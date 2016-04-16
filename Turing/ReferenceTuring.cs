using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography.Turing
{
    public class ReferenceTuring : Turing
    {
        protected override ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV)
        {
            return new ReferenceTuringTransform(rgbKey, rgbIV, Padding);
        }
    }

    public class ReferenceTuringTransform : TuringTransform
    {
        bool _disposed = false;

        public ReferenceTuringTransform(byte[] key, byte[] iv, PaddingMode paddingMode)
            : base(key, iv, paddingMode)
        {
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed state (managed objects).
                }

                // Free unmanaged resources (unmanaged objects)

                // Set large fields to null.

                _disposed = true;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Key the cipher.
        /// </summary>
        /// <param name="key"></param>
        /// <remarks>
        /// Reference version; merely gathers words, mixes them, saves them.
        /// </remarks>
        protected override void SetKey(byte[] key)
        {
            Debug.Assert(key.Length % 4 == 0);

            _key = new uint[key.Length / 4];
            int j = 0;
            for (int i = 0; i < key.Length; i += 4)
                _key[j++] = FixedS(ConvertBytesToWord(key, i));

            PseudoHadamardTransform(_key);
        }

        protected override ArraySegment<byte> GetNextRound()
        {
            uint a, b, c, d, e;

            StepRegister();
            a = _register[16];  b = _register[13];  c = _register[6];   d = _register[1];   e = _register[0];
            PseudoHadamardTransform(ref a, ref b, ref c, ref d, ref e);
            a = KeyedS(a, 0);   b = KeyedS(b, 8);   c = KeyedS(c, 16);  d = KeyedS(d, 24);  e = KeyedS(e, 0);
            PseudoHadamardTransform(ref a, ref b, ref c, ref d, ref e);
            StepRegister();
            StepRegister();
            StepRegister();
            a += _register[14]; b += _register[12]; c += _register[8];  d += _register[1];  e += _register[0];
            StepRegister();

            byte[] buffer = new byte[20];
            ConvertWordToBytes(a, buffer, 0);
            ConvertWordToBytes(b, buffer, 4);
            ConvertWordToBytes(c, buffer, 8);
            ConvertWordToBytes(d, buffer, 12);
            ConvertWordToBytes(e, buffer, 16);
            return new ArraySegment<byte>(buffer);
        }
    }
}
