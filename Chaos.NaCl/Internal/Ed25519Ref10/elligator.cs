using static Chaos.NaCl.Internal.Ed25519Ref10.GroupOperations;
using static Chaos.NaCl.Internal.Ed25519Ref10.LookupTables;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    internal static partial class FieldOperations
    {
        public static bool Elligator(byte[] representative, int representativeOffset, byte[] privateKey, int privatekeyOffset)
        {
            GroupElementP3 AA;

            //byte[] h = Sha512.Hash(privateKey, privatekeyOffset, 32);//ToDo: Remove alloc
            ScalarOperations.sc_clamp(privateKey, privatekeyOffset);

            ge_scalarmult_base(out AA, privateKey, privatekeyOffset);

            FieldElement inv1;
            fe_sub(out inv1, ref AA.Z, ref AA.Y); /* edwards25519.FeSub(&inv1, &A.Z, &A.Y) */
            fe_mul(out inv1, ref inv1, ref AA.X);     /* edwards25519.FeMul(&inv1, &inv1, &A.X) */
            fe_invert(out inv1, ref inv1);      /* edwards25519.FeInvert(&inv1, &inv1) */

            FieldElement t0, u;
            fe_mul(out u, ref inv1, ref AA.X);  /* edwards25519.FeMul(&u, &inv1, &A.X) */
            fe_add(out t0, ref AA.Y, ref AA.Z); /* edwards25519.FeAdd(&t0, &A.Y, &A.Z) */
            fe_mul(out u, ref u, ref t0);          /* edwards25519.FeMul(&u, &u, &t0) */

            FieldElement v;
            fe_mul(out v, ref t0, ref inv1);    /* edwards25519.FeMul(&v, &t0, &inv1) */
            fe_mul(out v, ref v, ref AA.Z);        /* edwards25519.FeMul(&v, &v, &A.Z) */
            fe_mul(out v, ref v, ref sqrtMinusA);  /* edwards25519.FeMul(&v, &v, &sqrtMinusA) */

            FieldElement b;
            fe_add(out b, ref u, ref A);        /* edwards25519.FeAdd(&b, &u, &edwards25519.A) */

            FieldElement c, b3, b8;
            fe_sq(out b3, ref b);           /* edwards25519.FeSquare(&b3, &b) // 2 */
            fe_mul(out b3, ref b3, ref b);          /* edwards25519.FeMul(&b3, &b3, &b) // 3 */
            fe_sq(out c, ref b3);           /* edwards25519.FeSquare(&c, &b3) // 6 */
            fe_mul(out c, ref c, ref b);           /* edwards25519.FeMul(&c, &c, &b) // 7 */
            fe_mul(out b8, ref c, ref b);       /* edwards25519.FeMul(&b8, &c, &b) // 8 */
            fe_mul(out c, ref c, ref u);           /* edwards25519.FeMul(&c, &c, &u) */
            q58(out c, ref c);          /* q58(&c, &c) */

            FieldElement chi;
            fe_sq(out chi, ref c);          /* edwards25519.FeSquare(&chi, &c) */
            fe_sq(out chi, ref chi);           /* edwards25519.FeSquare(&chi, &chi) */

            fe_sq(out t0, ref u);           /* edwards25519.FeSquare(&t0, &u) */
            fe_mul(out chi, ref chi, ref t0);        /* edwards25519.FeMul(&chi, &chi, &t0) */

            fe_sq(out t0, ref b);           /* edwards25519.FeSquare(&t0, &b) // 2 */
            fe_mul(out t0, ref t0, ref b);          /* edwards25519.FeMul(&t0, &t0, &b) // 3 */
            fe_sq(out t0, ref t0);            /* edwards25519.FeSquare(&t0, &t0) // 6 */
            fe_mul(out t0, ref t0, ref b);          /* edwards25519.FeMul(&t0, &t0, &b) // 7 */
            fe_sq(out t0, ref t0);            /* edwards25519.FeSquare(&t0, &t0) // 14 */
            fe_mul(out chi, ref chi, ref t0);        /* edwards25519.FeMul(&chi, &chi, &t0) */
            fe_neg(out chi, ref chi);          /* edwards25519.FeNeg(&chi, &chi) */

            var chiBytes = new byte[32];
            fe_tobytes(chiBytes, 0, ref chi);  /*edwards25519.FeToBytes(&chiBytes, &chi) */
                                               // chi[1] is either 0 or 0xff
            if (chiBytes[1] == 0xff)
            {
                return false;
            }

            // Calculate r1 = sqrt(-u/(2*(u+A)))
            FieldElement r1;
            fe_mul(out r1, ref c, ref u);       /* edwards25519.FeMul(&r1, &c, &u) */
            fe_mul(out r1, ref r1, ref b3);         /* edwards25519.FeMul(&r1, &r1, &b3) */
            fe_mul(out r1, ref r1, ref sqrtMinusHalf);  /* edwards25519.FeMul(&r1, &r1, &sqrtMinusHalf) */

            FieldElement maybeSqrtM1;
            fe_sq(out t0, ref r1);          /* edwards25519.FeSquare(&t0, &r1) */
            fe_mul(out t0, ref t0, ref b);          /* edwards25519.FeMul(&t0, &t0, &b) */
            fe_add(out t0, ref t0, ref t0);         /* edwards25519.FeAdd(&t0, &t0, &t0) */
            fe_add(out t0, ref t0, ref u);          /* edwards25519.FeAdd(&t0, &t0, &u) */

            fe_1(out maybeSqrtM1);  /* edwards25519.FeOne(&maybeSqrtM1) */
            fe_cmov(ref maybeSqrtM1, ref sqrtm1, fe_isnonzero(ref t0)); /* edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0)) */
            fe_mul(out r1, ref r1, ref maybeSqrtM1);/* edwards25519.FeMul(&r1, &r1, &maybeSqrtM1) */

            // Calculate r = sqrt(-(u+A)/(2u))
            FieldElement r;
            fe_sq(out t0, ref c);           /* edwards25519.FeSquare(&t0, &c) // 2 */
            fe_mul(out t0, ref t0, ref c);          /* edwards25519.FeMul(&t0, &t0, &c) // 3 */
            fe_sq(out t0, ref t0);            /* edwards25519.FeSquare(&t0, &t0) // 6 */
            fe_mul(out r, ref t0, ref c);       /* edwards25519.FeMul(&r, &t0, &c) // 7 */

            fe_sq(out t0, ref u);           /* edwards25519.FeSquare(&t0, &u) // 2 */
            fe_mul(out t0, ref t0, ref u);          /* edwards25519.FeMul(&t0, &t0, &u) // 3 */
            fe_mul(out r, ref r, ref t0);          /* edwards25519.FeMul(&r, &r, &t0) */

            fe_sq(out t0, ref b8);          /* edwards25519.FeSquare(&t0, &b8) // 16 */
            fe_mul(out t0, ref t0, ref b8);         /* edwards25519.FeMul(&t0, &t0, &b8) // 24 */
            fe_mul(out t0, ref t0, ref b);          /* edwards25519.FeMul(&t0, &t0, &b) // 25 */
            fe_mul(out r, ref r, ref t0);          /* edwards25519.FeMul(&r, &r, &t0) */
            fe_mul(out r, ref r, ref sqrtMinusHalf); /* edwards25519.FeMul(&r, &r, &sqrtMinusHalf) */

            fe_sq(out t0, ref r);           /* edwards25519.FeSquare(&t0, &r) */
            fe_mul(out t0, ref t0, ref u);          /* edwards25519.FeMul(&t0, &t0, &u) */
            fe_add(out t0, ref t0, ref t0);         /* edwards25519.FeAdd(&t0, &t0, &t0) */
            fe_add(out t0, ref t0, ref b);          /* edwards25519.FeAdd(&t0, &t0, &b) */
            fe_1(out maybeSqrtM1);  /* edwards25519.FeOne(&maybeSqrtM1) */
            fe_cmov(ref maybeSqrtM1, ref sqrtm1, fe_isnonzero(ref t0)); /* edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0)) */
            fe_mul(out r, ref r, ref maybeSqrtM1); /* edwards25519.FeMul(&r, &r, &maybeSqrtM1) */

            var vBytes = new byte[32];
            fe_tobytes(vBytes, 0, ref v);  /* edwards25519.FeToBytes(&vBytes, &v) */
            var vInSquareRootImage = fe_bytesLE(ref vBytes, ref halfQMinus1Bytes); /* vInSquareRootImage := feBytesLE(&vBytes, &halfQMinus1Bytes) */
            fe_cmov(ref r, ref r1, vInSquareRootImage); /* edwards25519.FeCMove(&r, &r1, vInSquareRootImage) */

            /*
             /* 5.5: Here |b| means b if b in {0, 1, ..., (q - 1)/2}, otherwise -b. 
            +uint8_t rBytes[32];
            +r.toBytes(rBytes);
            +unsigned int negateB = (1 & ~feBytesLE(rBytes, halfQMinus1Bytes));
            +r1.neg(r);
            +r.cmov(r1, negateB);
            */
            var rbytes = new byte[32];
            fe_tobytes(rbytes,0, ref r);
            var negateB = (1 & ~fe_bytesLE(ref rbytes, ref halfQMinus1Bytes));
            fe_neg(out r1, ref r);
            fe_cmov(ref r, ref r1, negateB);

            var pub = new byte[32];
            fe_tobytes(pub,0, ref u);
            fe_tobytes(representative, representativeOffset, ref r);  /* edwards25519.FeToBytes(representative, &r) */
            return true;
        }


        public static void RepresentativeToPublicKey(byte[] publicKey, int publickeyOffset, byte[] representative, int representativeOffset)
        {
            FieldElement rr2, v, e;

            fe_frombytes(out rr2, representative, representativeOffset);

            fe_sq2(out rr2, ref rr2);
            rr2.x0++;
            fe_invert(out rr2, ref rr2);
            fe_mul(out v, ref A, ref rr2);
            fe_neg(out v, ref v);

            FieldElement v2, v3;
            fe_sq(out v2, ref v);
            fe_mul(out v3, ref v, ref v2);
            fe_add(out e, ref v3, ref v);
            fe_mul(out v2, ref v2, ref A);
            fe_add(out e, ref v2, ref e);

            chi(out e, ref e);

            var eBytes = new byte[32];
            fe_tobytes(eBytes, 0, ref e);
            var eIsMinus1 = eBytes[1] & 1;

            FieldElement negV;
            fe_neg(out negV, ref v);
            fe_cmov(ref v, ref negV, eIsMinus1);
            fe_0(out v2);
            fe_cmov(ref v2, ref A, eIsMinus1);
            fe_sub(out v, ref v, ref v2);
            fe_tobytes(publicKey, publickeyOffset, ref v);
        }
    }
}