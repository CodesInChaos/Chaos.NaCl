namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    internal static partial class FieldOperations

    {
        public static void q58(out FieldElement o, ref FieldElement z)
        {
            FieldElement t1, t2, t3;
            int i;
            fe_sq(out t1, ref z); /* edwards25519.FeSquare(&t1, z) // 2^1 */
            fe_mul(out t1, ref z, ref t1); /* edwards25519.FeMul(&t1, &t1, z) // 2^1 + 2^0 */
            fe_sq(out t1, ref t1); /* edwards25519.FeSquare(&t1, &t1) // 2^2 + 2^1 */
            fe_sq(out t2, ref t1); /* edwards25519.FeSquare(&t2, &t1) // 2^3 + 2^2 */
            fe_sq(out t2, ref t2); /* edwards25519.FeSquare(&t2, &t2) // 2^4 + 2^3 */
            fe_mul(out t2, ref t1, ref t2); /* edwards25519.FeMul(&t2, &t2, &t1) // 4,3,2,1 */
            fe_mul(out t1, ref t2, ref z); /* edwards25519.FeMul(&t1, &t2, z) // 4..0 */
            fe_sq(out t2, ref t1); /* edwards25519.FeSquare(&t2, &t1) // 5..1 */
            for (i = 1; i < 5; i++)
            {
                // 9,8,7,6,5
                fe_sq(out t2, ref t2); /* edwards25519.FeSquare(&t2, &t2) */
            }
            fe_mul(out t1, ref t2, ref t1); /* edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0 */
            fe_sq(out t2, ref t1); /* edwards25519.FeSquare(&t2, &t1) // 10..1 */
            for (i = 1; i < 10; i++)
            {
                // 19..10 
                fe_sq(out t2, ref t2); /*edwards25519.FeSquare(&t2, &t2) */
            }
            fe_mul(out t2, ref t1, ref t2); /* edwards25519.FeMul(&t2, &t2, &t1) // 19..0 */
            fe_sq(out t3, ref t2); /* edwards25519.FeSquare(&t3, &t2) // 20..1 */
            for (i = 1; i < 20; i++)
            {
                // 39..20
                fe_sq(out t3, ref t3); /* edwards25519.FeSquare(&t3, &t3) */
            }
            fe_mul(out t2, ref t3, ref t2); /* edwards25519.FeMul(&t2, &t3, &t2) // 39..0 */
            fe_sq(out t2, ref t2); /* edwards25519.FeSquare(&t2, &t2) // 40..1 */
            for (i = 1; i < 10; i++)
            {
                // 49..10
                fe_sq(out t2, ref t2); /* edwards25519.FeSquare(&t2, &t2) */
            }
            fe_mul(out t1, ref t2, ref t1); /* edwards25519.FeMul(&t1, &t2, &t1) // 49..0 */
            fe_sq(out t2, ref t1); /* edwards25519.FeSquare(&t2, &t1) // 50..1 */
            for (i = 1; i < 50; i++)
            {
                // 99..50
                fe_sq(out t2, ref t2); /* edwards25519.FeSquare(&t2, &t2) */
            }
            fe_mul(out t2, ref t1, ref t2); /* edwards25519.FeMul(&t2, &t2, &t1) // 99..0 */
            fe_sq(out t3, ref t2); /* edwards25519.FeSquare(&t3, &t2) // 100..1 */
            for (i = 1; i < 100; i++)
            {
                // 199..100
                fe_sq(out t3, ref t3); /* edwards25519.FeSquare(&t3, &t3) */
            }
            fe_mul(out t2, ref t3, ref t2); /* edwards25519.FeMul(&t2, &t3, &t2) // 199..0 */
            fe_sq(out t2, ref t2); /* edwards25519.FeSquare(&t2, &t2) // 200..1 */
            for (i = 1; i < 50; i++)
            {
                // 249..50
                fe_sq(out t2, ref t2); /* edwards25519.FeSquare(&t2, &t2) */
            }
            fe_mul(out t1, ref t2, ref t1); /* edwards25519.FeMul(&t1, &t2, &t1) // 249..0 */
            fe_sq(out t1, ref t1); /* edwards25519.FeSquare(&t1, &t1) // 250..1 */
            fe_sq(out t1, ref t1); /* edwards25519.FeSquare(&t1, &t1) // 251..2 */
            fe_mul(out o, ref t1, ref z); /* edwards25519.FeMul(out, &t1, z) // 251..2,0 */
        }
    }
}