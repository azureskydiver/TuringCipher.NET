using System;
using System.Collections.Generic;
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

        protected override ArraySegment<byte> GetNextRound()
        {
            throw new NotImplementedException();
        }

        protected override void SetIV(byte[] iv)
        {
            throw new NotImplementedException();
        }

        protected override void SetKey(byte[] key)
        {
            throw new NotImplementedException();
        }
    }
}
