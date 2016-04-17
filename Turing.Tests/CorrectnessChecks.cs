using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace AXFSoftware.Security.Cryptography.Turing.Tests
{
    public static class CorrectnessChecks
    {
        static readonly byte[] FirstBlock =
        {
            0x69, 0x66, 0x26, 0xbb, 0xdc, 0x6e, 0x09, 0xf6,
            0xda, 0x9a, 0xba, 0xb5, 0xb5, 0x6c, 0x14, 0x87,
            0x82, 0x46, 0xdf, 0x18
        };

        static readonly byte[] StreamBlock =
        {
            0x5d, 0xa8, 0x8c, 0xed, 0x8a, 0xa6, 0x55, 0xba,
            0x78, 0x08, 0xef, 0xf8, 0xcf, 0x32, 0x63, 0xc0,
            0x75, 0xe4, 0x40, 0x3c,
        };

        const int StreamIndex = 9999;
        const int MaxRoundBytes = 17 * 20;

        public static void Encrypt(Func<byte[], byte[], PaddingMode, TuringTransform> create)
        {
            byte[] key = Encoding.ASCII.GetBytes("test key 128bits");
            byte[] iv = { 0, 0, 0, 0 };
            var transform = create(key, iv, PaddingMode.Zeros);

            byte[] clearText = new byte[TuringTransform.BlockSizeBytes + StreamIndex + MaxRoundBytes];
            for (int i = 0; i < clearText.Length; i++)
                clearText[i] = 0;

            byte[] cipherText = new byte[clearText.Length];

            int count = transform.TransformBlock(clearText, 0, TuringTransform.BlockSizeBytes,
                                                 cipherText, 0);

            Assert.Equal(20, TuringTransform.BlockSizeBytes);
            Assert.Equal(TuringTransform.BlockSizeBytes, count);
            Assert.Equal(FirstBlock, cipherText.Take(FirstBlock.Length));

            while (count < StreamIndex + TuringTransform.BlockSizeBytes)
            {
                count += transform.TransformBlock(clearText, count, TuringTransform.BlockSizeBytes,
                                                  cipherText, count);
            }
            Assert.Equal(StreamBlock, cipherText.Skip(StreamIndex).Take(StreamBlock.Length));
        }
    }

}
