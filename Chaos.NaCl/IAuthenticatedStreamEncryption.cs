using System;
using System.Collections.Generic;

namespace Chaos.NaCl
{
    public interface IAuthenticatedStreamEncryption : IDisposable
    {
        int KeySizeInBytes { get; }
        int NonceSizeInBytes { get; }
        int MacSizeInBytes { get; }

        byte[] Encrypt(byte[] message, byte[] nonce);
        void Encrypt(ArraySegment<byte> ciphertext, ArraySegment<byte> message, ArraySegment<byte> nonce);

        byte[] TryDecrypt(byte[] ciphertext, byte[] nonce);
        bool TryDecrypt(ArraySegment<byte> plaintext, ArraySegment<byte> ciphertext, ArraySegment<byte> nonce);
        //byte[] Decrypt(byte[] ciphertext, byte[] nonce);
    }
}
