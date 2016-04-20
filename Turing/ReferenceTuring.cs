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
    public class ReferenceTuring : Turing
    {
        protected override ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV)
        {
            return new ReferenceTuringTransform(rgbKey, rgbIV, Padding);
        }
    }

    public partial class ReferenceTuringTransform : TuringTransform
    {
        protected const int RegisterLength = 17;

        bool _disposed = false;
        protected uint[] _key;
        protected uint[] _register = new uint[RegisterLength];

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
                _key = null;
                _register = null;

                _disposed = true;
            }

            base.Dispose(disposing);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static uint ConvertBytesToWord(byte[] data, int offset)
        {
            uint word = data[offset++];
            word <<= 8;
            word |= data[offset++];
            word <<= 8;
            word |= data[offset++];
            word <<= 8;
            word |= data[offset++];
            return word;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static void ConvertWordToBytes(uint word, byte[] data, int offset)
        {
            var b3 = (byte)word;
            word >>= 8;
            var b2 = (byte)word;
            word >>= 8;
            var b1 = (byte)word;
            word >>= 8;

            data[offset++] = (byte)word;
            data[offset++] = b1;
            data[offset++] = b2;
            data[offset  ] = b3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static byte GetByteFromWord(uint word, int position)
        {
            return (byte)((word >> (24 - 8 * position)) & 0xFF);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static uint RotateLeft(uint word, int rotation)
        {
            return (word << rotation) | ((word >> ~rotation) >> 1);
        }

        protected void StepRegister()
        {
            uint w;
            w = _register[15] ^
                 _register[4] ^
                (_register[0] << 8) ^
                MultiplicationTable[(_register[0] >> 24) & 0xFF];

            for (int i = 1; i < RegisterLength; i++)
                _register[i - 1] = _register[i];
            _register[RegisterLength - 1] = w;
        }

        /// <summary>
        /// This does a reversible transformation of a word based on the
        /// S-boxes.
        /// </summary>
        /// <param name="w"></param>
        /// <returns></returns>
        /// <remarks>
        /// The reversibility isn't used, but it guarantees no loss of
        /// information, and hence no equivalent keys or IVs.
        /// </remarks>
        protected uint FixedS(uint w)
        {
            uint b;
            b = SBox[GetByteFromWord(w, 0)];    w = ((w ^            QBox[b]     ) & 0x00FFFFFF) | (b << 24);
            b = SBox[GetByteFromWord(w, 1)];    w = ((w ^ RotateLeft(QBox[b],  8)) & 0xFF00FFFF) | (b << 16);
            b = SBox[GetByteFromWord(w, 2)];    w = ((w ^ RotateLeft(QBox[b], 16)) & 0xFFFF00FF) | (b << 8);
            b = SBox[GetByteFromWord(w, 3)];    w = ((w ^ RotateLeft(QBox[b], 24)) & 0xFFFFFF00) |  b;
            return w;
        }

        /// <summary>
        /// Push a word through the keyed S-boxes.
        /// </summary>
        /// <param name="w">word to push through S-boxes</param>
        /// <param name="rotation">initial rotation</param>
        /// <returns></returns>
        /// <remarks>
        /// <para>
        /// As the bytes bounce around the permutation table, they are used
        /// to build up words from the Qbox entries. Then the byte position
        /// corresponding to the input byte is replaced with the result of
        /// the S-box, which is a permutation of the input and guarantees
        /// a balanced function.
        /// </para>
        /// <para>
        /// Also added a rotation of the input word, to combat a differential
        /// trail allowed by the PHT.
        /// </para>
        /// </remarks>
        protected virtual uint KeyedS(uint w, int rotation)
        {
            w = RotateLeft(w, rotation);

            byte[] b = new byte[4];
            ConvertWordToBytes(w, b, 0);

            uint[] ws = new uint[4];
            ws[0] = 0;
            ws[1] = 0;
            ws[2] = 0;
            ws[3] = 0;

            for (int i = 0; i < _key.Length; i++)
            {
                b[0] = SBox[GetByteFromWord(_key[i], 0) ^ b[0]]; ws[0] ^= RotateLeft(QBox[b[0]], i +  0);
                b[1] = SBox[GetByteFromWord(_key[i], 1) ^ b[1]]; ws[1] ^= RotateLeft(QBox[b[1]], i +  8);
                b[2] = SBox[GetByteFromWord(_key[i], 2) ^ b[2]]; ws[2] ^= RotateLeft(QBox[b[2]], i + 16);
                b[3] = SBox[GetByteFromWord(_key[i], 3) ^ b[3]]; ws[3] ^= RotateLeft(QBox[b[3]], i + 24);
            }

            w  = (ws[0] & 0x00FFFFFF) | ((uint)b[0] << 24);
            w ^= (ws[1] & 0xFF00FFFF) | ((uint)b[1] << 16);
            w ^= (ws[2] & 0xFFFF00FF) | ((uint)b[2] << 8);
            w ^= (ws[3] & 0xFFFFFF00) |        b[3];

            return w;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static void PseudoHadamardTransform(uint[] words)
        {
            int lastIndex = words.Length - 1;
            uint sum = 0;

            for (int i = 0; i < lastIndex; i++)
                sum += words[i];
            words[lastIndex] += sum;
            sum = words[lastIndex];
            for (int i = 0; i < lastIndex; i++)
                words[i] += sum;
        }

        protected override void SetKey(byte[] key)
        {
            Debug.Assert(key.Length % 4 == 0);

            _key = new uint[key.Length / 4];
            int j = 0;
            for (int i = 0; i < key.Length; i += 4)
                _key[j++] = FixedS(ConvertBytesToWord(key, i));

            PseudoHadamardTransform(_key);
        }

        protected override void SetIV(byte[] iv)
        {
            int i = 0;

            for (int j = 0; j < iv.Length; j += 4)
                _register[i++] = FixedS(ConvertBytesToWord(iv, j));

            _key.CopyTo(_register, i);
            i += _key.Length;

            uint lengthDependentWord = (uint)_key.Length << 4;
            lengthDependentWord |= (uint)iv.Length >> 2;
            lengthDependentWord |= 0x01020300;
            _register[i++] = lengthDependentWord;

            for (int j = 0; i < RegisterLength; i++, j++)
                _register[i] = KeyedS(_register[j] + _register[i - 1], 0);

            PseudoHadamardTransform(_register);
        }

        protected override ArraySegment<byte> GetNextRound()
        {
            Block block;

            StepRegister();
            block.A = _register[16];
                block.B = _register[13];
                    block.C = _register[6];
                        block.D = _register[1];
                            block.E = _register[0];
            block.PseudoHadamardTransform();
            block.A = KeyedS(block.A, 0);
                block.B = KeyedS(block.B, 8);
                    block.C = KeyedS(block.C, 16);
                        block.D = KeyedS(block.D, 24);
                            block.E = KeyedS(block.E, 0);
            block.PseudoHadamardTransform();
            StepRegister();
            StepRegister();
            StepRegister();
            block.A += _register[14];
                block.B += _register[12];
                    block.C += _register[8];
                        block.D += _register[1];
                            block.E += _register[0];
            StepRegister();

            byte[] buffer = new byte[BlockSizeBytes];
            block.CopyTo(buffer, 0);
            return new ArraySegment<byte>(buffer);
        }
    }
}
