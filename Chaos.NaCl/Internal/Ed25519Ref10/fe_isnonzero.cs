using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
	internal static partial class FieldOperations
	{
		/*
		return 1 if f == 0
		return 0 if f != 0

		Preconditions:
		   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
		*/
		private static byte[] zeroBytes = new byte[32];
		internal static int fe_isnonzero(ref FieldElement f)
		{
			byte[] bytes = new byte[32];//ToDo remove alloc
			fe_tobytes(bytes, 0, ref f);
			var result = Helpers.crypto_verify_32(bytes, zeroBytes);
			CryptoBytes.Wipe(bytes);
			return result;
		}
	}
}