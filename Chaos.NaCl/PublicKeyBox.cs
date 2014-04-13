using System;
using System.Collections.Generic;

namespace Chaos.NaCl
{
    public abstract class PublicKeyBox
    {
        public abstract int PublicKeySizeInBytes { get; }
        public abstract int PrivateKeySizeInBytes { get; }
        public abstract int NonceSizeInBytes { get; }
        public abstract int MacSizeInBytes { get; }

        public abstract IAuthenticatedStreamEncryption Create(byte[] publicKey, byte[] privateKey);
        public abstract IAuthenticatedStreamEncryption Create(ArraySegment<byte> publicKey, ArraySegment<byte> privateKey);

        private static readonly PublicKeyBox _curve25519XSalsa20Poly1305 = new PublicKeyBoxCurve25519XSalsa20Poly1305();
        public static PublicKeyBox Curve25519XSalsa20Poly1305 { get { return _curve25519XSalsa20Poly1305; } }
    }

    internal class PublicKeyBoxCurve25519XSalsa20Poly1305 : PublicKeyBox
    {
        public override int PublicKeySizeInBytes
        {
            get { return 32; }
        }

        public override int PrivateKeySizeInBytes
        {
            get { return 32; }
        }

        public override int NonceSizeInBytes
        {
            get { return 24; }
        }

        public override int MacSizeInBytes
        {
            get { return 16; }
        }

        public override IAuthenticatedStreamEncryption Create(byte[] publicKey, byte[] privateKey)
        {
            return Create(new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
        }

        public override IAuthenticatedStreamEncryption Create(ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
        {
            var sharedKey = new byte[32];
            MontgomeryCurve25519.KeyExchange(new ArraySegment<byte>(sharedKey), publicKey, privateKey);
            var result = new XSalsa20Poly1305(sharedKey, 0);
            CryptoBytes.Wipe(sharedKey);
            return result;
        }
    }
}
