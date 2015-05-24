namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    internal static partial class FieldOperations
    {
        public static void chi(out FieldElement o, ref FieldElement z)
        {
            FieldElement t0, t1, t2, t3;
            int i;
            fe_sq(out t0, ref z); // 2^1
            fe_mul(out t1, ref t0, ref z); // 2^1 + 2^0
            fe_sq(out t0, ref t1); // 2^2 + 2^1
            fe_sq(out t2, ref t0); // 2^3 + 2^2
            fe_sq(out t2, ref t2); // 4,3
            fe_mul(out t2, ref t2, ref t0); // 4,3,2,1
            fe_mul(out t1, ref t2, ref z); // 4..0
            fe_sq(out t2, ref t1); // 5..1
            for (i = 1; i < 5; i++)
            {
                // 9,8,7,6,5
                fe_sq(out t2, ref t2);
            }
            fe_mul(out t1, ref t2, ref t1); // 9,8,7,6,5,4,3,2,1,0
            fe_sq(out t2, ref t1); // 10..1
            for (i = 1; i < 10; i++)
            {
                // 19..10
                fe_sq(out t2, ref t2);
            }
            fe_mul(out t2, ref t2, ref t1); // 19..0
            fe_sq(out t3, ref t2); // 20..1
            for (i = 1; i < 20; i++)
            {
                // 39..20
                fe_sq(out t3, ref t3);
            }
            fe_mul(out t2, ref t3, ref t2); // 39..0
            fe_sq(out t2, ref t2); // 40..1
            for (i = 1; i < 10; i++)
            {
                // 49..10
                fe_sq(out t2, ref t2);
            }
            fe_mul(out t1, ref t2, ref t1); // 49..0
            fe_sq(out t2, ref t1); // 50..1
            for (i = 1; i < 50; i++)
            {
                // 99..50
                fe_sq(out t2, ref t2);
            }
            fe_mul(out t2, ref t2, ref t1); // 99..0
            fe_sq(out t3, ref t2); // 100..1
            for (i = 1; i < 100; i++)
            {
                // 199..100
                fe_sq(out t3, ref t3);
            }
            fe_mul(out t2, ref t3, ref t2); // 199..0
            fe_sq(out t2, ref t2); // 200..1
            for (i = 1; i < 50; i++)
            {
                // 249..50
                fe_sq(out t2, ref t2);
            }
            fe_mul(out t1, ref t2, ref t1); // 249..0
            fe_sq(out t1, ref t1); // 250..1
            for (i = 1; i < 4; i++)
            {
                // 253..4
                fe_sq(out t1, ref t1);
            }
            fe_mul(out o, ref t1, ref t0); // 253..4,2,1
        }
    }
}