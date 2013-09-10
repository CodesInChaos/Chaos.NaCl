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
                throw new ArgumentOutOfRangeException("xOffset", "xOffset < 0");
            if (y == null)
                throw new ArgumentNullException("y");
            if (yOffset < 0)
                throw new ArgumentOutOfRangeException("yOffset", "yOffset < 0");
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", "length < 0");
            if ((uint)xOffset + (uint)length > (uint)x.Length)
                throw new ArgumentOutOfRangeException("length", "xOffset + length > x.Length");
            if ((uint)yOffset + (uint)length > (uint)y.Length)
                throw new ArgumentOutOfRangeException("length", "yOffset + length > y.Length");

            return InternalConstantTimeEquals(x, xOffset, y, yOffset, length) != 0;
        }

        private static uint InternalConstantTimeEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length)
        {
            int differentbits = 0;
            for (int i = 0; i < length; i++)
                differentbits |= x[xOffset + i] ^ y[yOffset + i];
            return (1 & (((uint)differentbits - 1) >> 8));
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

        // Secure wiping is hard
        // * the GC can move around and copy memory
        //   Perhaps this can be avoided by using unmanaged memory or by fixing the position of the array in memory
        // * Swap files and error dumps can contain secret information
        //   It seems possible to lock memory in RAM, no idea about error dumps
        // * Compiler could optimize out the wiping if it knows that data won't be read back
        //   I hope this pure managed implementation is enough, suppressing inlining and optimization
        //   but perhaps `RtlSecureZeroMemory` is needed
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static void InternalWipe(byte[] data, int offset, int count)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");
            if (count < 0)
                throw new ArgumentOutOfRangeException("count", "Requires count >= 0");
            if ((uint)offset + (uint)count > (uint)data.Length)
                throw new ArgumentOutOfRangeException("count", "Requires offset + count <= data.Length");
            for (int i = 0; i < count; i++)
                data[offset + i] = 0;
        }

        public static string ToHexStringUpper(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "");
        }

        public static string ToHexStringLower(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "").ToLowerInvariant();
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
