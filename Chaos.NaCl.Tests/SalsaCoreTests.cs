using System;
using System.Linq;
using Chaos.NaCl.Internal;
using Chaos.NaCl.Internal.Salsa;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
	[TestClass]
	public class SalsaCoreTests
	{
		private T[] ToArray<T>(Array16<T> a)
		{
			var result = new T[16];
			result[0] = a.x0;
			result[1] = a.x1;
			result[2] = a.x2;
			result[3] = a.x3;
			result[4] = a.x4;
			result[5] = a.x5;
			result[6] = a.x6;
			result[7] = a.x7;
			result[8] = a.x8;
			result[9] = a.x9;
			result[10] = a.x10;
			result[11] = a.x11;
			result[12] = a.x12;
			result[13] = a.x13;
			result[14] = a.x14;
			result[15] = a.x15;
			return result;
		}

		[TestMethod]
		public void Zero()
		{
			Array16<UInt32> input = new Array16<uint>();
			Array16<UInt32> output;
			UInt32[] expected = new UInt32[16];
			SalsaCore.Salsa(out output, ref input, 20);
			Assert.IsTrue(ToArray(output).SequenceEqual(expected));
		}

		[TestMethod]
		public void DoubleRound1()
		{
			Array16<UInt32> input = new Array16<uint>();
			input.x0 = 1;
			Array16<UInt32> output;
			UInt32[] expected = new UInt32[16]
			{
				0x8186a22d,0x0040a284,0x82479210,0x06929051,
				0x08000090,0x02402200,0x00004000,0x00800000,
				0x00010200,0x20400000,0x08008104,0x00000000,
				0x20500000,0xa0000040,0x0008180a,0x612a8020
			};
			SalsaCore.HSalsa(out output, ref input, 2);
			Assert.IsTrue(ToArray(output).SequenceEqual(expected));
		}

		[TestMethod]
		public void Salsa20()
		{
			byte[] input = new byte[64]{
				211,159, 13,115, 76, 55, 82,183,3,117,222, 37,191,187,234,136,
				49,237,179, 48,1,106,178,219,175,199,166, 48, 86, 16,179,207,
				31,240, 32, 63, 15, 83, 93,161,116,147, 48,113,238, 55,204, 36,
				79,201,235, 79,3, 81,156, 47,203, 26,244,243, 88,118,104, 54};
			byte[] expectedOutput = new byte[64]{
				109, 42,178,168,156,240,248,238,168,196,190,203, 26,110,170,154,
				29, 29,150, 26,150, 30,235,249,190,163,251, 48, 69,144, 51, 57,
				118, 40,152,157,180, 57, 27, 94,107, 42,236, 35, 27,111,114,114,
				219,236,232,135,111,155,110, 18, 24,232, 95,158,179, 19, 48,202};
			byte[] actualOutput = new byte[64];
			Array16<UInt32> inputState;
			Array16<UInt32> outputState;

			ByteIntegerConverter.Array16LoadLittleEndian32(out inputState, input, 0);
			SalsaCore.Salsa(out outputState, ref inputState, 20);
			ByteIntegerConverter.Array16StoreLittleEndian32(actualOutput, 0, ref outputState);

		    TestHelpers.AssertEqualBytes(expectedOutput, actualOutput);
		}

		[TestMethod]
		public void Salsa20_1000000()
		{
			byte[] input = new byte[64]{
				6,124, 83,146, 38,191,9, 50,4,161, 47,222,122,182,223,185,
				75, 27,0,216, 16,122,7, 89,162,104,101,147,213, 21, 54, 95,
				225,253,139,176,105,132, 23,116, 76, 41,176,207,221, 34,157,108,
				94, 94, 99, 52, 90,117, 91,220,146,190,239,143,196,176,130,186};
			byte[] expectedOutput = new byte[64]{
				8, 18, 38,199,119, 76,215, 67,173,127,144,162,103,212,176,217,
				192, 19,233, 33,159,197,154,160,128,243,219, 65,171,136,135,225,
				123, 11, 68, 86,237, 82, 20,155,133,189,9, 83,167,116,194, 78,
				122,127,195,185,185,204,188, 90,245,9,183,248,226, 85,245,104};
			byte[] actualOutput = new byte[64];
			Array16<UInt32> state;
			ByteIntegerConverter.Array16LoadLittleEndian32(out state, input, 0);
			for (int i = 0; i < 1000000; i++)
			{
				SalsaCore.Salsa(out state, ref state, 20);
			}
			ByteIntegerConverter.Array16StoreLittleEndian32(actualOutput, 0, ref state);

			TestHelpers.AssertEqualBytes(expectedOutput, actualOutput);
		}
	}
}
