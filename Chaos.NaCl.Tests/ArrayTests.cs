using System;
using System.Collections.Generic;
using System.Linq;
using Chaos.NaCl.Internal;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    [TestClass]
    public class ArrayTests
    {
        private static readonly byte[] _testInput = Enumerable.Repeat((byte)0xFF, 100).Concat(Enumerable.Range(1, 250).Select(i => (byte)i)).ToArray();

        /*[TestMethod]
        public void Array8FromBytesLittleEndian()
        {
            for (int len = 1; len <= 32; len++)
            {
                Array8<UInt32> arr;
                ByteIntegerConverter.Array8LoadLittleEndian32(out arr, _testInput, 100, len);
                byte[] output = new byte[32];
                ByteIntegerConverter.Array8StoreLittleEndian32(output, 0, ref arr);
                byte[] expectedOutput = Enumerable.Range(1, len).Select(i => (byte)i).Concat(Enumerable.Repeat((byte)0x00, 32 - len)).ToArray();
                TestHelpers.AssertEqualBytes(expectedOutput, output));
            }
        }*/

        /*[TestMethod]
        public void Array16FromBytesLittleEndian()
        {
            for (int len = 1; len <= 64; len++)
            {
                Array16<UInt32> arr;
                ByteIntegerConverter.Array16LoadLittleEndian32(out arr, _testInput, 100, len);
                byte[] output = new byte[64];
                ByteIntegerConverter.Array16StoreLittleEndian32(output, 0, ref arr);
                byte[] expectedOutput = Enumerable.Range(1, len).Select(i => (byte)i).Concat(Enumerable.Repeat((byte)0x00, 64 - len)).ToArray();
                TestHelpers.AssertEqualBytes(expectedOutput, output));
            }
        }*/
    }
}
