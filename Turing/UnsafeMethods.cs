using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AXFSoftware.Security.Cryptography.Turing
{
    internal static class UnsafeMethods
    {
        public static Func<int, byte[], int, byte[], int, byte[], int, int> XorBytes;

        static UnsafeMethods()
        {
            if (IntPtr.Size == 8)
                XorBytes = XorBytes64;
            else
                XorBytes = XorBytes32;
        }

        public static unsafe int XorBytes64(int count,
                                            byte[] inputBuffer, int inputOffset,
                                            byte[] streamBuffer, int streamOffset,
                                            byte[] outputBuffer, int outputOffset)
        {
            Debug.Assert(count % sizeof(uint) == 0);

            fixed (byte* clear = &inputBuffer[inputOffset],
                         crypt = &streamBuffer[streamOffset],
                         cipher = &outputBuffer[outputOffset])
            {
                var end = &clear[count];
                var src64 = (UInt64*)clear;
                var pad64 = (UInt64*)crypt;
                var dst64 = (UInt64*)cipher;
                var end64 = &src64[count / sizeof(UInt64)];

                while (src64 < end64)
                    *dst64++ = *src64++ ^ *pad64++;

                var src32 = (UInt32*)src64;
                var pad32 = (UInt32*)pad64;
                var dst32 = (UInt32*)dst64;

                while (src32 < end)
                    *dst32++ = *src32++ ^ *pad32++;
            }
            return count;
        }

        public static unsafe int XorBytes32(int count,
                                            byte[] inputBuffer, int inputOffset,
                                            byte[] streamBuffer, int streamOffset,
                                            byte[] outputBuffer, int outputOffset)
        {
            Debug.Assert(count % sizeof(uint) == 0);

            fixed (byte* clear = &inputBuffer[inputOffset],
                         crypt = &streamBuffer[streamOffset],
                         cipher = &outputBuffer[outputOffset])
            {
                var end = &clear[count];
                var src = (uint*)clear;
                var pad = (uint*)crypt;
                var dst = (uint*)cipher;
                while (src < end)
                    *dst++ = *src++ ^ *pad++;
            }
            return count;
        }
    }
}
