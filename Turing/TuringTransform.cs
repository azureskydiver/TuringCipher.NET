using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography.Turing
{
    public abstract partial class TuringTransform : ICryptoTransform, IDisposable
    {
        public const int KeySizeMinBytes = 4;
        public const int KeySizeMinBits = KeySizeMinBytes * 8;
        public const int KeySizeMaxBytes = 32;
        public const int KeySizeMaxBits = KeySizeMaxBytes * 8;
        public const int KeySizeSkipBytes = 4;
        public const int KeySizeSkipBits = KeySizeSkipBytes * 8;
        public const int IVSizeMinBytes = 4;
        public const int IVSizeMinBits = IVSizeMinBytes * 8;
        public const int KeyIVMaxBytes = 48;
        public const int KeyIVMaxBits = KeyIVMaxBytes * 8;
        public const int BlockSizeBytes = 20;
        public const int BlockSize = BlockSizeBytes * 8;
        const int LinearFeedbackShiftRegisterLength = 17;

        bool _disposed = false;
        PaddingMode _padding;
        protected uint[] _key;
        protected uint[] _register = new uint[LinearFeedbackShiftRegisterLength];

        public int InputBlockSize => BlockSize;
        public int OutputBlockSize => BlockSize;
        public bool CanTransformMultipleBlocks => true;
        public bool CanReuseTransform => false;

        public TuringTransform(byte [] key, byte [] iv, PaddingMode paddingMode)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length < KeySizeMinBytes || key.Length > KeySizeMaxBytes)
                throw new ArgumentOutOfRangeException(nameof(key), $"Must be between {KeySizeMinBytes} and {KeySizeMaxBytes} bytes");
            if (key.Length % KeySizeSkipBytes != 0)
                throw new ArgumentOutOfRangeException(nameof(key), $"Must be a multiple of {KeySizeSkipBytes} bytes");

            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            if (iv.Length < IVSizeMinBytes)
                throw new ArgumentOutOfRangeException(nameof(iv), $"Must be at least {IVSizeMinBytes} bytes");

            if (key.Length + iv.Length > KeyIVMaxBytes)
                throw new ArgumentOutOfRangeException(nameof(iv), $"Key and IV length must be less than {KeyIVMaxBytes} bytes");

            if (paddingMode == PaddingMode.None)
                throw new ArgumentOutOfRangeException(nameof(paddingMode), "Padding cannot be None");

            _padding = paddingMode;

            SetKey(key);
            SetIV(iv);
        }

        ~TuringTransform()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
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
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected abstract void SetKey(byte[] key);
        protected abstract ArraySegment<byte> GetNextRound();

        protected uint ConvertBytesToWord(byte [] data, int offset)
        {
            throw new NotImplementedException();
        }

        protected byte [] ConvertWordToBytes(uint word)
        {
            throw new NotImplementedException();
        }

        protected byte GetByteFromWord(uint word, int position)
        {
            throw new NotImplementedException();
        }

        protected uint RotateLeft(uint word, int rotation)
        {
            Debug.Assert(rotation >= 0);
            if (rotation != 0)
                word = (word << rotation) | (word >> (32 - rotation));
            return word;
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
            b = SBox[GetByteFromWord(w, 0)]; w = ((w ^            QBox[b]     ) & 0x00FFFFFF) | (b << 24);
            b = SBox[GetByteFromWord(w, 1)]; w = ((w ^ RotateLeft(QBox[b],  8)) & 0xFF00FFFF) | (b << 16);
            b = SBox[GetByteFromWord(w, 2)]; w = ((w ^ RotateLeft(QBox[b], 16)) & 0xFFFF00FF) | (b <<  8);
            b = SBox[GetByteFromWord(w, 3)]; w = ((w ^ RotateLeft(QBox[b], 24)) & 0xFFFFFF00) |  b;
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
        protected uint SFunction(uint w, int rotation)
        {
            w = RotateLeft(w, rotation);

            byte[] b = ConvertWordToBytes(w);
            uint[] ws = new uint[4];

            ws[0] = 0;
            ws[1] = 0;
            ws[2] = 0;
            ws[3] = 0;
            for(int i = 0; i < _key.Length; i++)
            {
                b[0] = SBox[GetByteFromWord(_key[i], 0) ^ b[0]]; ws[0] ^= RotateLeft(QBox[b[0]], i + 0);
                b[1] = SBox[GetByteFromWord(_key[i], 1) ^ b[1]]; ws[1] ^= RotateLeft(QBox[b[1]], i + 8);
                b[2] = SBox[GetByteFromWord(_key[i], 2) ^ b[2]]; ws[2] ^= RotateLeft(QBox[b[2]], i + 16);
                b[3] = SBox[GetByteFromWord(_key[i], 3) ^ b[3]]; ws[3] ^= RotateLeft(QBox[b[3]], i + 24);
            }

            w  = ((uint)ws[0] & 0x00FFFFFF) | ((uint)b[0] << 24);
            w ^= ((uint)ws[1] & 0xFF00FFFF) | ((uint)b[1] << 16);
            w ^= ((uint)ws[2] & 0xFFFF00FF) | ((uint)b[2] << 8);
            w ^= ((uint)ws[3] & 0xFFFFFF00) |        b[3];

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

        protected void PseudoHadamardTransform(uint [] words)
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

        protected virtual void SetIV(byte[] iv)
        {
            int i = 0;

            for(int j = 0; j < iv.Length; j += 4)
                _register[i++] = FixedS(ConvertBytesToWord(iv, j));

            _key.CopyTo(_register, i);
            i += _key.Length;

            uint lengthDependentWord = (uint)_key.Length << 4;
            lengthDependentWord |= (uint)iv.Length >> 2;
            lengthDependentWord |= 0x01020300;
            _register[i++] = lengthDependentWord;

            for (int j = 0; i < _register.Length; i++, j++)
                _register[i] = SFunction(_register[j] + _register[i - 1], 0);

            PseudoHadamardTransform(_register);
        }

        void CheckInputParameters(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException(nameof(inputOffset), "Must be offset into the input buffer");
            if (inputOffset > inputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputOffset), "Must not exceed size of input buffer");
            if (inputCount < 0)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Must be greater than or equal to zero");
            if (inputCount > inputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Must not exceed size of input buffer");
            if (inputOffset + inputCount > inputBuffer.Length)
                throw new InvalidOperationException($"{nameof(inputOffset)} + {nameof(inputCount)} must not exceed size of input buffer");
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount,
                                  byte[] outputBuffer, int outputOffset)
        {
            CheckInputParameters(inputBuffer, inputOffset, inputCount);
            if (inputCount % BlockSize != 0)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Must be multiple of block size.");
            if (inputCount > outputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(inputCount), "Must not exceed size of output buffer");

            if (outputOffset < 0)
                throw new ArgumentOutOfRangeException(nameof(outputOffset), "Must be offset into the output buffer");
            if (outputOffset > outputBuffer.Length)
                throw new ArgumentOutOfRangeException(nameof(outputOffset), "Must not exceed size of output buffer");
            if (outputOffset + inputCount > outputBuffer.Length)
                throw new InvalidOperationException($"{nameof(outputOffset)} + {nameof(inputCount)} must not exceed size of output buffer");

            for (int i = 0; i < inputCount; i += BlockSizeBytes)
            {
                var segment = GetNextRound();
                byte [] pad = segment.Array;
                int segmentOffset = segment.Offset;
                int count = segment.Count;
                while (count-- > 0)
                    outputBuffer[outputOffset++] = (byte)(inputBuffer[inputOffset++] ^ pad[segmentOffset++]);
            }

            return inputCount;
        }

        byte [] GetPaddedBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var padded = new byte[BlockSizeBytes];
            for(int i = 0; i < inputCount; i++)
                padded[i] = inputBuffer[inputOffset + i];

            byte pad = 0;
            switch (_padding)
            {
            case PaddingMode.ANSIX923:
            case PaddingMode.Zeros:
                break;

            case PaddingMode.PKCS7:
                pad = (byte)(padded.Length - inputCount);
                break;

            case PaddingMode.None:
            default:
                Debug.Assert(false, "Constructor should have caught this.");
                break;
            }

            if (_padding != PaddingMode.ISO10126)
            {
                for (int i = inputCount; i < padded.Length; i++)
                    padded[i] = pad;
            }
            else
            {
                // Do nothing. ISO10126 indicates need for random data.
                // We'll use whatever is in the array that was allocated.
            }

            return padded;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            CheckInputParameters(inputBuffer, inputOffset, inputCount);

            var padded = GetPaddedBlock(inputBuffer, inputOffset, inputCount);
            var block = new byte[BlockSizeBytes];
            TransformBlock(padded, 0, padded.Length, block, 0);
            return block;
        }
    }
}
