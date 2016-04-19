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
            int z0 = z % RegisterLength;
            uint r0 = _register[z0];

            _register[z0] = _register[RegisterOffset(z, 15)] ^ 
                            _register[RegisterOffset(z, 4)] ^
	                        (r0 << 8) ^
                            MultiplicationTable[(r0 >> 24) & 0xFF];
        }

        int RegisterOffset(int zero, int offset)
        {
            return (zero + offset) % RegisterLength;
        }

        protected uint KeyedS0(Word word)
        {
            return _keyedSBox[0][word.Byte0] ^
                   _keyedSBox[1][word.Byte1] ^
                   _keyedSBox[2][word.Byte2] ^
                   _keyedSBox[3][word.Byte3];
        }

        protected uint KeyedS1(Word word)
        {
            return _keyedSBox[0][word.Byte1] ^
                   _keyedSBox[1][word.Byte2] ^
                   _keyedSBox[2][word.Byte3] ^
                   _keyedSBox[3][word.Byte0];
        }

        protected uint KeyedS2(Word word)
        {
            return _keyedSBox[0][word.Byte2] ^
                   _keyedSBox[1][word.Byte3] ^
                   _keyedSBox[2][word.Byte0] ^
                   _keyedSBox[3][word.Byte1];
        }

        protected uint KeyedS3(Word word)
        {
            return _keyedSBox[0][word.Byte3] ^
                   _keyedSBox[1][word.Byte0] ^
                   _keyedSBox[2][word.Byte1] ^
                   _keyedSBox[3][word.Byte2];
        }

        void DoRound(int z, byte [] buffer, int offset)
        {
            uint a, b, c, d, e;

            StepRegister(z);
            a = _register[RegisterOffset(z + 1, 16)];
		        b = _register[RegisterOffset(z + 1, 13)];
			        c = _register[RegisterOffset(z + 1, 6)];
					    d = _register[RegisterOffset(z + 1, 1)];
						    e = _register[RegisterOffset(z + 1, 0)];
            PseudoHadamardTransform(ref a, ref b, ref c, ref d, ref e);
            a = KeyedS0(a); b = KeyedS1(b); c = KeyedS2(c); d = KeyedS3(d); e = KeyedS0(e);
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
        }

        byte [] GetNextRounds()
        {
            byte[] buffer = new byte[RegisterLength * BlockSizeBytes];

            DoRound( 0, buffer,   0);
            DoRound( 5, buffer,  20);
            DoRound(10, buffer,  40);
            DoRound(15, buffer,  60);
            DoRound( 3, buffer,  80);
            DoRound( 8, buffer, 100);
            DoRound(13, buffer, 120);
            DoRound( 1, buffer, 140);
            DoRound( 6, buffer, 160);
            DoRound(11, buffer, 180);
            DoRound(16, buffer, 200);
            DoRound( 4, buffer, 220);
            DoRound( 9, buffer, 240);
            DoRound(14, buffer, 260);
            DoRound( 2, buffer, 280);
            DoRound( 7, buffer, 300);
            DoRound(12, buffer, 320);
            return buffer;
        }

        protected override ArraySegment<byte> GetNextRound()
        {
            if (_rounds.Count == 0)
            {
                byte[] buffer = GetNextRounds();
                for (int offset = 0; offset < buffer.Length; offset += BlockSizeBytes)
                    _rounds.Enqueue(new ArraySegment<byte>(buffer, offset, BlockSizeBytes));
            }
            return _rounds.Dequeue();
        }
    }
}
