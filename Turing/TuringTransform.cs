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

        bool _disposed = false;
        PaddingMode _padding;

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
        protected abstract void SetIV(byte[] iv);
        protected abstract ArraySegment<byte> GetNextRound();

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
