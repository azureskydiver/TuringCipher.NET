#define LITTLE_ENDIAN

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace AXFSoftware.Security.Cryptography.Turing
{
    /// <summary>
    /// Maps a native unsigned 32-bit value to a set of Big Endian bytes.
    /// </summary>
    /// 
    /// <remarks>
    /// The Turing cipher follows a Big Endian convention where the first byte
    /// is the most significant. So a value of 0x12345678 has Byte0 == 0x12,
    /// Byte1 == 0x34, Byte2 == 0x56, and Byte3 == 0x78.
    /// </remarks>
    [StructLayout(LayoutKind.Explicit, Pack = 1, Size = 4)]
    public struct Word : IComparable, IComparable<Word>, IEquatable<Word>
    {
        [FieldOffset(0)]
        public uint Value;

#if LITTLE_ENDIAN
        [FieldOffset(0)]
        public byte Byte3;
        [FieldOffset(1)]
        public byte Byte2;
        [FieldOffset(2)]
        public byte Byte1;
        [FieldOffset(3)]
        public byte Byte0;
#else
        [FieldOffset(0)]
        public byte Byte0;
        [FieldOffset(1)]
        public byte Byte1;
        [FieldOffset(2)]
        public byte Byte2;
        [FieldOffset(3)]
        public byte Byte3;
#endif

        public byte this[int index]
        {
            get
            {
                switch (index)
                {
                    case 0: return Byte0;
                    case 1: return Byte1;
                    case 2: return Byte2;
                    case 3: return Byte3;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(index));
                }
            }

            set
            {
                switch (index)
                {
                    case 0: Byte0 = value; break;
                    case 1: Byte1 = value; break;
                    case 2: Byte2 = value; break;
                    case 3: Byte3 = value; break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(index));
                }
            }
        }

        public byte[] GetBytes()
        {
            return new byte[] { Byte0, Byte1, Byte2, Byte3 };
        }

        public static Word FromBytes(byte[] bytes, int offset = 0)
        {
            return new Word
                    {
                        Byte0 = bytes[offset + 0],
                        Byte1 = bytes[offset + 1],
                        Byte2 = bytes[offset + 2],
                        Byte3 = bytes[offset + 3]
                    };
        }


        public static implicit operator Word(uint value)
        {
            return new Word() { Value = value };
        }

        public static explicit operator uint(Word w)
        {
            return w.Value;
        }

        public static bool operator ==(Word a, Word b)
        {
            return a.Value == b.Value;
        }

        public static bool operator !=(Word a, Word b)
        {
            return a.Value != b.Value;
        }

        public static bool operator <(Word a, Word b)
        {
            return a.Value < b.Value;
        }

        public static bool operator >(Word a, Word b)
        {
            return a.Value > b.Value;
        }

        public static bool operator <=(Word a, Word b)
        {
            return a.Value <= b.Value;
        }

        public static bool operator >=(Word a, Word b)
        {
            return a.Value >= b.Value;
        }

        public override bool Equals(object obj)
        {
            if (obj is Word)
            {
                Word other = (Word)obj;
                return Value == other.Value;
            }
            return false;
        }

        public bool Equals(Word other)
        {
            return this.Value == other.Value;
        }

        public override int GetHashCode()
        {
            return (int)Value;
        }

        public override string ToString()
        {
            return Value.ToString("X");
        }

        int IComparable.CompareTo(object obj)
        {
            if (obj == null)
                return 1;

            return this.CompareTo((Word)obj);
        }

        public int CompareTo(Word other)
        {
            if (this.Value == other.Value)
                return 0;
            if (this.Value < other.Value)
                return -1;
            return 1;
        }

        public static Word operator ^(Word a, Word b)
        {
            return new Word() { Value = a.Value ^ b.Value };
        }

        public static Word operator |(Word a, Word b)
        {
            return new Word() { Value = a.Value | b.Value };
        }

        public static Word operator &(Word a, Word b)
        {
            return new Word() { Value = a.Value & b.Value };
        }

        public static Word operator +(Word a, Word b)
        {
            return new Word() { Value = a.Value + b.Value };
        }

        public static Word operator -(Word a, Word b)
        {
            return new Word() { Value = a.Value - b.Value };
        }

        public static Word operator *(Word a, Word b)
        {
            return new Word() { Value = a.Value * b.Value };
        }

        public static Word operator /(Word a, Word b)
        {
            return new Word() { Value = a.Value / b.Value };
        }

        public static Word operator %(Word a, Word b)
        {
            return new Word() { Value = a.Value % b.Value };
        }

        public static Word operator <<(Word a, int shift)
        {
            return new Word() { Value = a.Value << shift };
        }

        public static Word operator >>(Word a, int shift)
        {
            return new Word() { Value = a.Value >> shift };
        }

        public static Word operator ~(Word a)
        {
            return new Word() { Value = ~a.Value };
        }

        public static Word operator ++(Word a)
        {
            ++a.Value;
            return a;
        }

        public static Word operator --(Word a)
        {
            --a.Value;
            return a;
        }
    }
}
