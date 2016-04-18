using System;
using System.Collections.Generic;
using System.Diagnostics;
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

        void StepRegister(int z)
        {
            _register[RegisterOffset(z, 0)] = _register[RegisterOffset(z, 15)] ^ 
                                              _register[RegisterOffset(z, 4)] ^
	                                          (_register[RegisterOffset(z, 0)] << 8) ^
                                              MultiplicationTable[(_register[RegisterOffset(z, 0)] >> 24) & 0xFF];
        }

        int RegisterOffset(int zero, int offset)
        {
            return (zero + offset) % RegisterLength;
        }

        protected override uint KeyedS(uint w, int b)
        {
            return _keyedSBox[0][GetByteFromWord(w, ((0 + b) & 0x3))] ^
                   _keyedSBox[1][GetByteFromWord(w, ((1 + b) & 0x3))] ^
                   _keyedSBox[2][GetByteFromWord(w, ((2 + b) & 0x3))] ^
                   _keyedSBox[3][GetByteFromWord(w, ((3 + b) & 0x3))];
        }

        ArraySegment<byte> DoRound(int z, byte [] buffer, int offset)
        {
            uint a, b, c, d, e;

            StepRegister(z);
            a = _register[RegisterOffset(z + 1, 16)];
		        b = _register[RegisterOffset(z + 1, 13)];
			        c = _register[RegisterOffset(z + 1, 6)];
					    d = _register[RegisterOffset(z + 1, 1)];
						    e = _register[RegisterOffset(z + 1, 0)];
            PseudoHadamardTransform(ref a, ref b, ref c, ref d, ref e);
            a = KeyedS(a, 0); b = KeyedS(b, 1); c = KeyedS(c, 2); d = KeyedS(d, 3); e = KeyedS(e, 0);
            PseudoHadamardTransform(ref a, ref b, ref c, ref d, ref e);
            StepRegister(z + 1);
            StepRegister(z + 2);
            StepRegister(z + 3);
            a += _register[RegisterOffset(z + 4, 14)];
		        b += _register[RegisterOffset(z + 4, 12)];
			        c += _register[RegisterOffset(z + 4, 8)];
					    d += _register[RegisterOffset(z + 4, 1)];
						    e += _register[RegisterOffset(z + 4, 0)];
            StepRegister(z + 4);
            ConvertWordToBytes(a, buffer, offset);
		        ConvertWordToBytes(b, buffer, offset + 4);
			            ConvertWordToBytes(c, buffer, offset + 8);
					        ConvertWordToBytes(d, buffer, offset + 12);
						            ConvertWordToBytes(e, buffer, offset + 16);

            return new ArraySegment<byte>(buffer, offset, BlockSizeBytes);
        }

        IEnumerable<ArraySegment<byte>> GetNextRounds()
        {
            var rounds = new List<ArraySegment<byte>>(RegisterLength);
            byte[] buffer = new byte[RegisterLength * BlockSizeBytes];

            rounds.Add(DoRound( 0, buffer,   0));
            rounds.Add(DoRound( 5, buffer,  20));
            rounds.Add(DoRound(10, buffer,  40));
            rounds.Add(DoRound(15, buffer,  60));
            rounds.Add(DoRound( 3, buffer,  80));
            rounds.Add(DoRound( 8, buffer, 100));
            rounds.Add(DoRound(13, buffer, 120));
            rounds.Add(DoRound( 1, buffer, 140));
            rounds.Add(DoRound( 6, buffer, 160));
            rounds.Add(DoRound(11, buffer, 180));
            rounds.Add(DoRound(16, buffer, 200));
            rounds.Add(DoRound( 4, buffer, 220));
            rounds.Add(DoRound( 9, buffer, 240));
            rounds.Add(DoRound(14, buffer, 260));
            rounds.Add(DoRound( 2, buffer, 280));
            rounds.Add(DoRound( 7, buffer, 300));
            rounds.Add(DoRound(12, buffer, 320));

            Debug.Assert(rounds.Count == RegisterLength);
            return rounds;
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
    }
}
