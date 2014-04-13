using System;

namespace Chaos.NaCl
{
    internal sealed class SecretBoxXSalsa20Poly1305 : SecretBox
    {
        public override IAuthenticatedStreamEncryption Create(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (key.Length != 32)
                throw new ArgumentException("key.Length must be 32");
            return new XSalsa20Poly1305(key, 0);
        }

        public override IAuthenticatedStreamEncryption Create(ArraySegment<byte> key)
        {
            if (key.Array == null)
                throw new ArgumentException("key.Array must not be null");
            if (key.Count != 32)
                throw new ArgumentException("key.Count must be 32");
            return new XSalsa20Poly1305(key.Array, key.Offset);
        }

        public override int KeySizeInBytes
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
    }
}