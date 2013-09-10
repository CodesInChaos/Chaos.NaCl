using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Chaos.NaCl.Internal
{
    internal class Sha512BclWrapper : SHA512Managed
    {
        public static void crypto_hash_sha512(byte[] output, byte[] input, int inputOffset, int inputLength)
        {
            using (var hasher = new Sha512BclWrapper())
            {
                var output0 = hasher.ComputeHash(input, inputOffset, inputLength);
                output0.CopyTo(output, 0);
            }
        }
    }
}
