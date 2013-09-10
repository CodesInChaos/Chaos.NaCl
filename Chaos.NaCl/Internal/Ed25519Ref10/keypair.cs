using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
	internal static partial class Ed25519Operations
	{
		public static void crypto_sign_keypair(byte[] pk, int pkoffset, byte[] sk, int skoffset, byte[] seed, int seedoffset)
		{
			byte[] h = new byte[64];//ToDo: Remove alloc
			GroupElementP3 A;
			int i;

			Array.Copy(seed, seedoffset, sk, skoffset, 32);
			Sha512BclWrapper.crypto_hash_sha512(h, sk, skoffset, 32);
			h[0] &= 248;
			h[31] &= 63;
			h[31] |= 64;

			GroupOperations.ge_scalarmult_base(out A, h, 0);
			GroupOperations.ge_p3_tobytes(pk, pkoffset, ref A);

			for (i = 0; i < 32; ++i) sk[skoffset + 32 + i] = pk[pkoffset + i];
			CryptoBytes.Wipe(h);
		}
	}
}
