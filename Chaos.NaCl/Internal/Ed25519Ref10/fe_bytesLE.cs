using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    internal static partial class FieldOperations
    {
        public static int fe_bytesLE(ref byte[] a, ref byte[] b)
        {
            var equalSoFar = -1;
            var greater = 0;
            for (var i = 31; i > 0; i--)
            {
                var x = a[i];
                var y = b[i];
                greater = (~equalSoFar & greater) | (equalSoFar & ((x - y) >> 31));
                equalSoFar = equalSoFar & (((x ^ y) - 1) >> 31);
            }
            return ~equalSoFar & 1 & greater;
        }
    }
}