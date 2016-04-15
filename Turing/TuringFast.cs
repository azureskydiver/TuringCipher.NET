using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography
{
    public class TuringFast : Turing
    {
        protected override ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV)
        {
            return new TuringFastTransform(rgbKey, rgbIV, Padding);
        }
    }

    public class TuringFastTransform : TuringTransform
    {
        bool _disposed = false;
        Queue<ArraySegment<byte>> _rounds = new Queue<ArraySegment<byte>>();

        public TuringFastTransform(byte[] key, byte[] iv, PaddingMode paddingMode)
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
                    _rounds?.Clear();
                }

                // Free unmanaged resources (unmanaged objects)

                // Set large fields to null.
                _rounds = null;

                _disposed = true;
            }

            base.Dispose(disposing);
        }

        protected override ArraySegment<byte> GetNextRound()
        {
            if (_rounds.Count == 0)
            {
                foreach (var round in GetNextRounds())
                    _rounds.Enqueue(round);
            }
            return _rounds.Dequeue();
        }

        protected override void SetIV(byte[] iv)
        {
            throw new NotImplementedException();
        }

        protected override void SetKey(byte[] key)
        {
            throw new NotImplementedException();
        }

        IEnumerable<ArraySegment<byte>> GetNextRounds()
        {
            throw new NotImplementedException();
        }
    }
}
