using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    internal static partial class Ed25519Operations
    {    
        public static void unmultiplied_a(byte[] ua, int uaoffset, byte[] seed, int seedoffset)
        {
            int i;
            
            byte[] h = Sha512.Hash(seed, seedoffset, 32);//ToDo: Remove alloc
            h[0] &= 248;
            h[31] &= 63;
            h[31] |= 64;
            
            for (i = 0; i < 32; ++i) ua[uaoffset + i] = h[i];
            CryptoBytes.Wipe(h);
        }
    }
}
