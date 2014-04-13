using System;

namespace Chaos.NaCl
{
    public abstract class SecretBox
    {
        public abstract int KeySizeInBytes { get; }
        public abstract int NonceSizeInBytes { get; }
        public abstract int MacSizeInBytes { get; }

        public abstract IAuthenticatedStreamEncryption Create(byte[] key);
        public abstract IAuthenticatedStreamEncryption Create(ArraySegment<byte> key);

        private static readonly SecretBoxXSalsa20Poly1305 _xSalsa20Poly1305 = new SecretBoxXSalsa20Poly1305();
        public static SecretBox XSalsa20Poly1305 { get { return _xSalsa20Poly1305; } }
    }
}
