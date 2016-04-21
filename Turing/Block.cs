using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography.Turing
{
    public partial class ReferenceTuringTransform : TuringTransform
    {
        [StructLayout(LayoutKind.Explicit, Pack = 1, Size = 4)]
        protected struct Block
        {
            [FieldOffset(0)]
            public uint A;
            [FieldOffset(4)]
            public uint B;
            [FieldOffset(8)]
            public uint C;
            [FieldOffset(12)]
            public uint D;
            [FieldOffset(16)]
            public uint E;

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void PseudoHadamardTransform()
            {
                E += A + B + C + D;
                A += E;
                B += E;
                C += E;
                D += E;
            }

            public unsafe void CopyTo(byte[] buffer, int offset)
            {
                fixed(uint* source = &this.A)
                fixed(byte* dest = &buffer[offset])
                {
                    uint* dst = (uint *)dest;
                    uint* src = source;

                    if (BitConverter.IsLittleEndian)
                    {
                        for (int i = 0; i < 5; i++)
                        {
                            uint w = *src++;
                            w = ((w & 0xFF00FF00) >> 8) | ((w & 0x00FF00FF) << 8);
                            *dst++ = (w >> 16) | (w << 16);
                        }
                    }
                    else
                    {
                        for (int i = 0; i < 5; i++)
                            *dst++ = *src++;
                    }
                }
            }
        }
    }
}
