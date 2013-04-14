using System;
using System.Runtime.CompilerServices;

namespace Chaos.NaCl
{
	public static class CryptoBytes
	{
		public static bool ContantTimeEquals(byte[] x, byte[] y)
		{
			return ContantTimeEquals(new ArraySegment<byte>(x), new ArraySegment<byte>(y));
		}

		public static bool ContantTimeEquals(ArraySegment<byte> x, ArraySegment<byte> y)
		{
			if (x.Count != y.Count)
				throw new ArgumentException("x.Count must equal y.Count");
			return ConstantTimeEquals(x.Array, x.Offset, y.Array, y.Offset, x.Count);
		}

		public static bool ConstantTimeEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length)
		{
			if (x == null)
				throw new ArgumentNullException("x");
			if (xOffset < 0)
				throw new ArgumentOutOfRangeException("x<0");
			if (y == null)
				throw new ArgumentNullException("y");
			if (yOffset < 0)
				throw new ArgumentOutOfRangeException("y<0");
			if (length < 0)
				throw new ArgumentOutOfRangeException("length<0");
			if ((uint)xOffset + (uint)length > (uint)x.Length)
				throw new ArgumentOutOfRangeException("xOffset+length>x.Length");
			if ((uint)yOffset + (uint)length > (uint)y.Length)
				throw new ArgumentOutOfRangeException("yOffset+length>y.Length");
			int differentbits = 0;
			for (int i = 0; i < length; i++)
				differentbits |= x[xOffset + i] ^ y[yOffset + i];
			return (1 & (((uint)differentbits - 1) >> 8)) != 0;
		}


		public static void Wipe(byte[] data)
		{
			InternalWipe(data, 0, data.Length);
		}

		public static void Wipe(byte[] data, int offset, int count)
		{
			InternalWipe(data, offset, count);
		}

		public static void Wipe(ArraySegment<byte> data)
		{
			InternalWipe(data.Array, data.Offset, data.Count);
		}

		// Secure wiping is hard, the GC can move around and copy memory
		// I hope this pure managed implementation is enough, suppressing inlining and optimization
		// but perhaps `RtlSecureZeroMemory` is needed
		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
		private static void InternalWipe(byte[] data, int offset, int count)
		{
			if (data == null)
				throw new ArgumentNullException("data");
			if (offset < 0)
				throw new ArgumentOutOfRangeException("offset");
			if (count < 0)
				throw new ArgumentOutOfRangeException("count");
			if ((uint)offset + (uint)count > (uint)data.Length)
				throw new ArgumentOutOfRangeException("offset+count");
			for (int i = 0; i < count; i++)
				data[offset + i] = 0;
		}

		public static string ToHexString(byte[] data)
		{
			return BitConverter.ToString(data).Replace("-", "");
		}

		public static byte[] FromHexString(string hexString)
		{
			if (hexString == null)
				return null;
			if (hexString.Length % 2 != 0)
				throw new ArgumentException("Invalid hexString");
			var result = new byte[hexString.Length / 2];
			for (int i = 0; i < result.Length; i++)
				result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
			return result;
		}

		public static string ToBase64String(byte[] data)
		{
			return Convert.ToBase64String(data);
		}

		public static byte[] FromBase64String(string s)
		{
			return Convert.FromBase64String(s);
		}
	}
}
