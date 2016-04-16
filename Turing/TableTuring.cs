using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography.Turing
{
    public class TableTuring : Turing
    {
        protected override ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV)
        {
            return new TableTuringTransform(rgbKey, rgbIV, Padding);
        }
    }

    public class TableTuringTransform : ReferenceTuringTransform
    {
        bool _disposed = false;
        protected uint[][] _keyedSBox = null;

        public TableTuringTransform(byte [] key, byte [] iv, PaddingMode paddingMode)
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
                if (_keyedSBox != null)
                {
                    for (int i = 0; i < 4; i++)
                        _keyedSBox[i] = null;
                }
                _keyedSBox = null;

                _disposed = true;
            }

            base.Dispose(disposing);
        }

        protected override void SetKey(byte[] key)
        {
            base.SetKey(key);
            ComputeKeyedSBoxes();
        }

        void ComputeKeyedSBoxes()
        {
            _keyedSBox = new uint[4][];
            for (int i = 0; i < 4; i++)
                _keyedSBox[i] = ComputeKeyedSBox(i);
        }

        uint [] ComputeKeyedSBox(int position)
        {
            uint[] keyed = new uint[256];
            int rotation = position * 8;
            int shift = (3 - position) * 8;

            uint mask = 0xFFFFFF00;
            mask = RotateLeft(mask, shift);
            
            for(byte j = 0; j <= 255; j++)
            {
                uint w = 0;
                byte k = j;
                for (int i = 0; i < _key.Length; i++)
                {
                    k = SBox[GetByteFromWord(_key[i], position) ^ k];
                    w ^= RotateLeft(QBox[k], i + rotation);
                }
                keyed[j] = (w & mask) | ((uint)k << shift);
            }

            return keyed;
        }

        protected override uint KeyedS(uint w, int rotation)
        {
            w = RotateLeft(w, rotation);
            return _keyedSBox[0][GetByteFromWord(w, 0)] ^ 
                   _keyedSBox[1][GetByteFromWord(w, 1)] ^ 
                   _keyedSBox[2][GetByteFromWord(w, 2)] ^ 
                   _keyedSBox[3][GetByteFromWord(w, 3)];
        }
    }
}
