using System;
using System.Collections.Generic;

namespace Chaos.NaCl.Internal
{
	internal static class ByteIntegerConverter
	{
		public static UInt32 LoadLittleEndian32(byte[] buf, int offset)
		{
			return
				(UInt32)(buf[offset + 0])
			| (((UInt32)(buf[offset + 1])) << 8)
			| (((UInt32)(buf[offset + 2])) << 16)
			| (((UInt32)(buf[offset + 3])) << 24);
		}

		public static void StoreLittleEndian32(byte[] buf, int offset, UInt32 value)
		{
			buf[offset + 0] = (byte)value;
			buf[offset + 1] = (byte)(value >> 8);
			buf[offset + 2] = (byte)(value >> 16);
			buf[offset + 3] = (byte)(value >> 24);
		}
	}
}
