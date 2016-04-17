using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AXFSoftware.Security.Cryptography.Turing;
using Xunit;

namespace AXFSoftware.Security.Cryptography.Turing.Tests
{
    public class Fast
    {
        [Fact]
        void CanCreateAlgorithmInstance()
        {
            Assert.NotNull(new FastTuring());
        }

        [Fact]
        void CanCreateTransformInstanceIndirectly()
        {
            var turing = new FastTuring();
            Assert.NotNull(turing);

            turing.GenerateKey();
            turing.GenerateIV();
            Assert.NotNull(turing.CreateEncryptor());
            Assert.NotNull(turing.CreateDecryptor());
        }

        [Fact]
        void CanCreateTransformInstanceDirectly()
        {
            byte[] key = Encoding.ASCII.GetBytes("open sesame!");
            byte[] iv = { 1, 2, 3, 4 };

            var transform = new FastTuringTransform(key, iv, PaddingMode.Zeros);
            Assert.NotNull(transform);
        }

        [Fact]
        void DoesBasicEncryptionCorrectly()
        {
            CorrectnessChecks.Encrypt((key, iv, pad) => new FastTuringTransform(key, iv, pad));
        }
    }
}
