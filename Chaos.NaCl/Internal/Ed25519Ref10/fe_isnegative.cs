using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
	internal static partial class FieldOperations
	{
		/*
		return 1 if f is in {1,3,5,...,q-2}
		return 0 if f is in {0,2,4,...,q-1}

		Preconditions:
		|f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
		*/
		//int fe_isnegative(const fe f)
		public static int fe_isnegative(ref FieldElement f)
		{
			var bytes = new byte[32];//ToDo: remove alloc
			fe_tobytes(bytes, 0, ref f);
			var result = bytes[0] & 1;
			CryptoBytes.Wipe(bytes);
			return result;
		}
	}
}