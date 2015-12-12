using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    internal static partial class LookupTables
    {
        internal static FieldElement sqrtm1 = new FieldElement(-32595792, -7943725, 9377950, 3500415, 12389472, -272473,
            -25146209, -2005654, 326686, 11406482);

        internal static FieldElement A = new FieldElement(486662, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        internal static FieldElement sqrtMinusA = new FieldElement(12222970, 8312128, 11511410, -9067497, 15300785,
            241793, -25456130, -14121551, 12187136, -3972024);

        internal static FieldElement sqrtMinusHalf = new FieldElement(-17256545, 3971863, 28865457, -1750208, 27359696,
            -16640980, 12573105, 1002827, -163343, 11073975);

        internal static byte[] halfQMinus1Bytes =
        {
            0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x3f
        };
    }
}