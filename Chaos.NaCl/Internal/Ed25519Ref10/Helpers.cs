using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
	internal static class Helpers
	{
		public static int crypto_verify_32(byte[] x, byte[] y)
		{
			int differentbits = 0;
			differentbits |= x[0] ^ y[0];
			differentbits |= x[1] ^ y[1];
			differentbits |= x[2] ^ y[2];
			differentbits |= x[3] ^ y[3];
			differentbits |= x[4] ^ y[4];
			differentbits |= x[5] ^ y[5];
			differentbits |= x[6] ^ y[6];
			differentbits |= x[7] ^ y[7];
			differentbits |= x[8] ^ y[8];
			differentbits |= x[9] ^ y[9];
			differentbits |= x[10] ^ y[10];
			differentbits |= x[11] ^ y[11];
			differentbits |= x[12] ^ y[12];
			differentbits |= x[13] ^ y[13];
			differentbits |= x[14] ^ y[14];
			differentbits |= x[15] ^ y[15];
			differentbits |= x[16] ^ y[16];
			differentbits |= x[17] ^ y[17];
			differentbits |= x[18] ^ y[18];
			differentbits |= x[19] ^ y[19];
			differentbits |= x[20] ^ y[20];
			differentbits |= x[21] ^ y[21];
			differentbits |= x[22] ^ y[22];
			differentbits |= x[23] ^ y[23];
			differentbits |= x[24] ^ y[24];
			differentbits |= x[25] ^ y[25];
			differentbits |= x[26] ^ y[26];
			differentbits |= x[27] ^ y[27];
			differentbits |= x[28] ^ y[28];
			differentbits |= x[29] ^ y[29];
			differentbits |= x[30] ^ y[30];
			differentbits |= x[31] ^ y[31];
			return (int)((1 & (((uint)differentbits - 1) >> 8)) - 1);
		}
	}
}
