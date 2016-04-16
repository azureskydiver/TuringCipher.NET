using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography.Turing
{
    public class FastTuring : Turing
    {
        protected override ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV)
        {
            return new FastTuringTransform(rgbKey, rgbIV, Padding);
        }
    }

    public class FastTuringTransform : TableTuringTransform
    {
        bool _disposed = false;
        Queue<ArraySegment<byte>> _rounds = new Queue<ArraySegment<byte>>();

        public FastTuringTransform(byte[] key, byte[] iv, PaddingMode paddingMode)
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

        IEnumerable<ArraySegment<byte>> GetNextRounds()
        {
            throw new NotImplementedException();
        }
    }
}
