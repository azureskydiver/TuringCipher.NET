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
                    byte* dst = dest;
                    uint* src = source;

                    for(int i = 0; i < 5; i++)
                    {
                        uint w = *src++;
                        var b3 = (byte)w;
                        w >>= 8;
                        var b2 = (byte)w;
                        w >>= 8;
                        var b1 = (byte)w;
                        w >>= 8;

                        *dst++ = (byte)w;
                        *dst++ = b1;
                        *dst++ = b2;
                        *dst++ = b3;
                    }
                }
            }
        }
    }
}
