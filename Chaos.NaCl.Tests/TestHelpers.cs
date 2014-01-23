using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    static class TestHelpers
    {
        private static readonly Random _random = new Random();
        private static readonly object _sync = new object();

        private static int Random(int min, int max)
        {
            lock (_sync)
            {
                return _random.Next(min, max);
            }
        }

        public static void AssertEqualBytes(byte[] expected, byte[] actual)
        {
            Assert.AreEqual(BitConverter.ToString(expected), BitConverter.ToString(actual));
        }

        public static ArraySegment<byte> Pad(this byte[] array)
        {
            return array.Pad(Random(1, 100), Random(0, 50));
        }

        private static ArraySegment<byte> Pad(this byte[] array, int paddingLeft, int paddingRight)
        {
            byte padByteLeft;
            byte padByteRight;
            if (array.Length > 0)
            {
                padByteLeft = (byte)~array[0];
                padByteRight = (byte)~array[array.Length - 1];
            }
            else
            {
                padByteLeft = 0xE7;
                padByteRight = 0xE7;
            }
            var resultBytes = Enumerable.Repeat(padByteLeft, paddingLeft).Concat(array).Concat(Enumerable.Repeat(padByteRight, paddingRight)).ToArray();
            return new ArraySegment<byte>(resultBytes, paddingLeft, array.Length);
        }

        public static IEnumerable<byte[]> WithChangedBit(this byte[] array)
        {
            for (int i = 0; i < array.Length; i++)
                for (int bit = 0; bit < 8; bit++)
                {
                    var result = array.ToArray();
                    result[i] ^= (byte)(1 << bit);
                    yield return result;
                }
        }

        public static byte[] ToArray(this ArraySegment<byte> segment)
        {
            var result = new byte[segment.Count];
            Array.Copy(segment.Array, segment.Offset, result, 0, segment.Count);
            return result;
        }
    }
}
