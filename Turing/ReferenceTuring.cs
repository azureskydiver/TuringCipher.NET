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
        protected uint[] _key;
        protected uint[] _register = new uint[17];

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

        protected uint ConvertBytesToWord(byte[] data, int offset)
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

        protected void ConvertWordToBytes(uint word, byte[] data, int offset)
        {
            offset += 3;
            data[offset--] = (byte)(word & 0xFF);
            word >>= 8;
            data[offset--] = (byte)(word & 0xFF);
            word >>= 8;
            data[offset--] = (byte)(word & 0xFF);
            word >>= 8;
            data[offset--] = (byte)(word & 0xFF);
            word >>= 8;
        }

        protected byte GetByteFromWord(uint word, int position)
        {
            return (byte)((word >> (24 - 8 * position)) & 0xFF);
        }

        protected uint RotateLeft(uint word, int rotation)
        {
            Debug.Assert(rotation >= 0);
            if (rotation != 0)
                word = (word << rotation) | (word >> (32 - rotation));
            return word;
        }

        protected void StepRegister()
        {
            uint w;
            w = _register[15] ^
                 _register[4] ^
                (_register[0] << 8) ^
                MultiplicationTable[(_register[0] >> 24) & 0xFF];

            for (int i = 1; i < _register.Length; i++)
                _register[i - 1] = _register[i];
            _register[_register.Length - 1] = w;
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

        protected void PseudoHadamardTransform(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e)
        {
            e += a + b + c + d;
            a += e;
            b += e;
            c += e;
            d += e;
        }

        protected void PseudoHadamardTransform(uint[] words)
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

            for (int j = 0; i < _register.Length; i++, j++)
                _register[i] = KeyedS(_register[j] + _register[i - 1], 0);

            PseudoHadamardTransform(_register);
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
