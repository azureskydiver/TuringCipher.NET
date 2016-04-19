using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
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
        static readonly int[] _registerOffset;

        static FastTuringTransform()
        {
            _registerOffset = new int[36];
            for (int z = 0; z < _registerOffset.Length; z++)
                _registerOffset[z] = z % RegisterLength;
        }

        bool _disposed = false;
        byte[] _buffer = new byte[RegisterLength * BlockSizeBytes];

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
                }

                // Free unmanaged resources (unmanaged objects)

                // Set large fields to null.
                _buffer = null;

                _disposed = true;
            }

            base.Dispose(disposing);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void StepRegister(int z)
        {
            int z0 = z % RegisterLength;
            uint r0 = _register[z0];

            _register[z0] = _register[_registerOffset[z + 15]] ^ 
                            _register[_registerOffset[z +  4]] ^
	                        (r0 << 8) ^
                            MultiplicationTable[(r0 >> 24) & 0xFF];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected uint KeyedS0(Word word)
        {
            return _keyedSBox[0][word.Byte0] ^
                   _keyedSBox[1][word.Byte1] ^
                   _keyedSBox[2][word.Byte2] ^
                   _keyedSBox[3][word.Byte3];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected uint KeyedS1(Word word)
        {
            return _keyedSBox[0][word.Byte1] ^
                   _keyedSBox[1][word.Byte2] ^
                   _keyedSBox[2][word.Byte3] ^
                   _keyedSBox[3][word.Byte0];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected uint KeyedS2(Word word)
        {
            return _keyedSBox[0][word.Byte2] ^
                   _keyedSBox[1][word.Byte3] ^
                   _keyedSBox[2][word.Byte0] ^
                   _keyedSBox[3][word.Byte1];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected uint KeyedS3(Word word)
        {
            return _keyedSBox[0][word.Byte3] ^
                   _keyedSBox[1][word.Byte0] ^
                   _keyedSBox[2][word.Byte1] ^
                   _keyedSBox[3][word.Byte2];
        }

        void DoRound(int z, int offset)
        {
            uint a, b, c, d, e;

            StepRegister(z);
            a = _register[_registerOffset[z + 1 + 16]];
		        b = _register[_registerOffset[z + 1 + 13]];
			        c = _register[_registerOffset[z + 1 + 6]];
					    d = _register[_registerOffset[z + 1 + 1]];
						    e = _register[_registerOffset[z + 1 + 0]];
            PseudoHadamardTransform(ref a, ref b, ref c, ref d, ref e);
            a = KeyedS0(a); b = KeyedS1(b); c = KeyedS2(c); d = KeyedS3(d); e = KeyedS0(e);
            PseudoHadamardTransform(ref a, ref b, ref c, ref d, ref e);
            StepRegister(z + 1);
            StepRegister(z + 2);
            StepRegister(z + 3);
            a += _register[_registerOffset[z + 4 + 14]];
		        b += _register[_registerOffset[z + 4 + 12]];
			        c += _register[_registerOffset[z + 4 + 8]];
					    d += _register[_registerOffset[z + 4 + 1]];
						    e += _register[_registerOffset[z + 4 + 0]];
            StepRegister(z + 4);
            ConvertWordToBytes(a, _buffer, offset);
		        ConvertWordToBytes(b, _buffer, offset + 4);
			            ConvertWordToBytes(c, _buffer, offset + 8);
					        ConvertWordToBytes(d, _buffer, offset + 12);
						            ConvertWordToBytes(e, _buffer, offset + 16);
        }

        void GetNextRounds()
        {
            DoRound( 0,   0);
            DoRound( 5,  20);
            DoRound(10,  40);
            DoRound(15,  60);
            DoRound( 3,  80);
            DoRound( 8, 100);
            DoRound(13, 120);
            DoRound( 1, 140);
            DoRound( 6, 160);
            DoRound(11, 180);
            DoRound(16, 200);
            DoRound( 4, 220);
            DoRound( 9, 240);
            DoRound(14, 260);
            DoRound( 2, 280);
            DoRound( 7, 300);
            DoRound(12, 320);
        }

        protected override ArraySegment<byte> GetNextRound()
        {
            GetNextRounds();
            return new ArraySegment<byte>(_buffer);
        }
    }
}
