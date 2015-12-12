using System;

using static Chaos.NaCl.Internal.Ed25519Ref10.FieldOperations;
using static Chaos.NaCl.Internal.Ed25519Ref10.GroupOperations;
using static Chaos.NaCl.Internal.Ed25519Ref10.LookupTables;
using static Chaos.NaCl.MontgomeryCurve25519;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    internal static partial class Ed25519Operations
    {
        public static void crypto_sign_keypair(byte[] pk, int pkoffset, byte[] sk, int skoffset, byte[] seed, int seedoffset)
        {
            GroupElementP3 A;
            int i;

            Array.Copy(seed, seedoffset, sk, skoffset, 32);
            byte[] h = Sha512.Hash(sk, skoffset, 32);//ToDo: Remove alloc
            ScalarOperations.sc_clamp(h, 0);

            ge_scalarmult_base(out A, h, 0);
            ge_p3_tobytes(pk, pkoffset, ref A);

            for (i = 0; i < 32; ++i) sk[skoffset + 32 + i] = pk[pkoffset + i];
            CryptoBytes.Wipe(h);
        }


        public static void crypto_ecdh_keypair(byte[] publicKey, byte[] privateKey)
        {
            ScalarOperations.sc_clamp(privateKey, 0);

            GroupElementP3 A;
            ge_scalarmult_base(out A, privateKey, 0);
            FieldElement publicKeyFE;
            EdwardsToMontgomeryX(out publicKeyFE, ref A.Y, ref A.Z);
            fe_tobytes(publicKey, 0, ref publicKeyFE);
        }
    }
}
