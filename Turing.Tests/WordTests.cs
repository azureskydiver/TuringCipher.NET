using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AXFSoftware.Security.Cryptography.Turing;
using Xunit;

namespace AXFSoftware.Security.Cryptography.Turing.Tests
{
    public class WordTests
    {
        [Fact]
        public void WordToBytesLineUp()
        {
            Word w = new Word() { Value = 0x12345678 };
            Assert.Equal(0x12, w.Byte0);
            Assert.Equal(0x34, w.Byte1);
            Assert.Equal(0x56, w.Byte2);
            Assert.Equal(0x78, w.Byte3);
        }

        [Fact]
        public void BytesToWordLineUp()
        {
            Word w = new Word() { Byte0 = 0x12, Byte1 = 0x34, Byte2 = 0x56, Byte3 = 0x78 };
            Assert.Equal((uint)0x12345678, w.Value);
        }

        [Fact]
        public void CanImplicitlyConvert()
        {
            Word w = 0xbaadf00d;
            Assert.Equal((uint)0xbaadf00d, w.Value);
        }

        [Fact]
        public void CanUseIndexerToRead()
        {
            Word w = 0xCAFEBABE;
            Assert.Equal(0xCA, w[0]);
            Assert.Equal(0xFE, w[1]);
            Assert.Equal(0xBA, w[2]);
            Assert.Equal(0xBE, w[3]);
        }

        [Fact]
        public void CanUseIndexerToWrite()
        {
            Word w = 0xdeadbeef;
            w[0] = 0xCA;
            w[1] = 0xFE;
            w[2] = 0xBA;
            w[3] = 0xBE;
            Assert.Equal(0xCAFEBABE, w.Value);
        }

        [Fact]
        public void IndexerThrowsOnOutOfRange()
        {
            Word w = 12;
            Assert.Throws<ArgumentOutOfRangeException>(() => w[-1] = 0x12);
            Assert.Throws<ArgumentOutOfRangeException>(() => w[4] = 0x12);
        }

        [Fact]
        public void IncrementAndDecrementWorks()
        {
            Word w = 12;
            ++w;
            Assert.Equal((uint)13, w.Value);

            --w;
            Assert.Equal((uint)12, w.Value);
        }
    }
}
