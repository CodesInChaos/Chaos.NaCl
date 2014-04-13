using System;
using System.Collections.Generic;
using Chaos.NaCl.Internal;
using Chaos.NaCl.Internal.Salsa;

namespace Chaos.NaCl
{
    internal class XSalsa20Poly1305 : IAuthenticatedStreamEncryption
    {
        private Array8<UInt32> _key;

        public int KeySizeInBytes { get { return 32; } }
        public int NonceSizeInBytes { get { return 24; } }
        public int MacSizeInBytes { get { return 16; } }

        internal XSalsa20Poly1305(byte[] key, int offset)
        {
            ByteIntegerConverter.Array8LoadLittleEndian32(out _key, key, offset);
        }

        public void Dispose()
        {
            CryptoBytes.InternalWipe(ref _key);
        }

        public byte[] Encrypt(byte[] message, byte[] nonce)
        {
            if (message == null)
                throw new ArgumentNullException("message");
            if (nonce == null)
                throw new ArgumentNullException("nonce");
            if (nonce.Length != NonceSizeInBytes)
                throw new ArgumentException("nonce.Length != 24");

            var ciphertext = new byte[message.Length + MacSizeInBytes];
            EncryptInternal(ciphertext, 0, message, 0, message.Length, nonce, 0);
            return ciphertext;
        }

        public void Encrypt(ArraySegment<byte> ciphertext, ArraySegment<byte> message, ArraySegment<byte> nonce)
        {
            if (nonce.Count != NonceSizeInBytes)
                throw new ArgumentException("nonce.Length != 24");
            if (ciphertext.Count != message.Count + MacSizeInBytes)
                throw new ArgumentException("ciphertext.Count != message.Count + MacSizeInBytes");
            EncryptInternal(ciphertext.Array, ciphertext.Offset, message.Array, message.Offset, message.Count, nonce.Array, nonce.Offset);
        }

        /// <summary>
        /// Decrypts the ciphertext and verifies its authenticity
        /// </summary>
        /// <returns>Plaintext if MAC validation succeeds, null if the data is invalid.</returns>
        public byte[] TryDecrypt(byte[] ciphertext, byte[] nonce)
        {
            if (ciphertext == null)
                throw new ArgumentNullException("ciphertext");
            if (nonce == null)
                throw new ArgumentNullException("nonce");
            if (nonce.Length != NonceSizeInBytes)
                throw new ArgumentException("nonce.Length != 24");

            if (ciphertext.Length < MacSizeInBytes)
                return null;
            var plaintext = new byte[ciphertext.Length - MacSizeInBytes];
            bool success = DecryptInternal(plaintext, 0, ciphertext, 0, ciphertext.Length, nonce, 0);
            if (success)
                return plaintext;
            else
                return null;
        }

        /// <summary>
        /// Decrypts the ciphertext and verifies its authenticity
        /// </summary>
        /// <param name="message">Plaintext if authentication succeeded, all zero if authentication failed, undefined if argument verification fails</param>
        /// <param name="ciphertext"></param>
        /// <param name="nonce">Must be identical to nonce specified for encryption.</param>
        /// <returns>true if ciphertext is authentic, false otherwise</returns>
        public bool TryDecrypt(ArraySegment<byte> message, ArraySegment<byte> ciphertext, ArraySegment<byte> nonce)
        {
            if (nonce.Count != NonceSizeInBytes)
                throw new ArgumentException("nonce.Length != 24");
            if (ciphertext.Count != message.Count + MacSizeInBytes)
                throw new ArgumentException("ciphertext.Count != message.Count + 16");

            return DecryptInternal(message.Array, message.Offset, ciphertext.Array, ciphertext.Offset, ciphertext.Count, nonce.Array, nonce.Offset);
        }

        private void PrepareInternalKey(out Array16<UInt32> internalKey, byte[] nonce, int nonceOffset)
        {
            internalKey.x0 = Salsa20.SalsaConst0;
            internalKey.x1 = _key.x0;
            internalKey.x2 = _key.x1;
            internalKey.x3 = _key.x2;
            internalKey.x4 = _key.x3;
            internalKey.x5 = Salsa20.SalsaConst1;
            internalKey.x6 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 0);
            internalKey.x7 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 4);
            internalKey.x8 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 8);
            internalKey.x9 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 12);
            internalKey.x10 = Salsa20.SalsaConst2;
            internalKey.x11 = _key.x4;
            internalKey.x12 = _key.x5;
            internalKey.x13 = _key.x6;
            internalKey.x14 = _key.x7;
            internalKey.x15 = Salsa20.SalsaConst3;
            SalsaCore.HSalsa(out internalKey, ref internalKey, 20);

            //key
            internalKey.x1 = internalKey.x0;
            internalKey.x2 = internalKey.x5;
            internalKey.x3 = internalKey.x10;
            internalKey.x4 = internalKey.x15;
            internalKey.x11 = internalKey.x6;
            internalKey.x12 = internalKey.x7;
            internalKey.x13 = internalKey.x8;
            internalKey.x14 = internalKey.x9;
            //const
            internalKey.x0 = Salsa20.SalsaConst0;
            internalKey.x5 = Salsa20.SalsaConst1;
            internalKey.x10 = Salsa20.SalsaConst2;
            internalKey.x15 = Salsa20.SalsaConst3;
            //nonce
            internalKey.x6 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 16);
            internalKey.x7 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 20);
            //offset
            internalKey.x8 = 0;
            internalKey.x9 = 0;
        }

        private bool DecryptInternal(byte[] plaintext, int plaintextOffset, byte[] ciphertext, int ciphertextOffset, int ciphertextLength, byte[] nonce, int nonceOffset)
        {
            int plaintextLength = ciphertextLength - MacSizeInBytes;
            Array16<UInt32> internalKey;
            PrepareInternalKey(out internalKey, nonce, nonceOffset);

            Array16<UInt32> temp;
            var tempBytes = new byte[64];//todo: remove allocation

            // first iteration
            {
                SalsaCore.Salsa(out temp, ref internalKey, 20);

                //first half is for Poly1305
                Array8<UInt32> poly1305Key;
                poly1305Key.x0 = temp.x0;
                poly1305Key.x1 = temp.x1;
                poly1305Key.x2 = temp.x2;
                poly1305Key.x3 = temp.x3;
                poly1305Key.x4 = temp.x4;
                poly1305Key.x5 = temp.x5;
                poly1305Key.x6 = temp.x6;
                poly1305Key.x7 = temp.x7;

                // compute MAC
                Poly1305Donna.poly1305_auth(tempBytes, 0, ciphertext, ciphertextOffset + 16, plaintextLength, ref poly1305Key);
                if (!CryptoBytes.ConstantTimeEquals(tempBytes, 0, ciphertext, ciphertextOffset, MacSizeInBytes))
                {
                    Array.Clear(plaintext, plaintextOffset, plaintextLength);
                    return false;
                }

                // rest for the message
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 0, temp.x8);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 4, temp.x9);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 8, temp.x10);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 12, temp.x11);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 16, temp.x12);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 20, temp.x13);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 24, temp.x14);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 28, temp.x15);
                int count = Math.Min(32, plaintextLength);
                for (int i = 0; i < count; i++)
                    plaintext[plaintextOffset + i] = (byte)(ciphertext[MacSizeInBytes + ciphertextOffset + i] ^ tempBytes[i]);
            }

            // later iterations
            int blockOffset = 32;
            while (blockOffset < plaintextLength)
            {
                internalKey.x8++;
                SalsaCore.Salsa(out temp, ref internalKey, 20);
                ByteIntegerConverter.Array16StoreLittleEndian32(tempBytes, 0, ref temp);
                int count = Math.Min(64, plaintextLength - blockOffset);
                for (int i = 0; i < count; i++)
                    plaintext[plaintextOffset + blockOffset + i] = (byte)(ciphertext[16 + ciphertextOffset + blockOffset + i] ^ tempBytes[i]);
                blockOffset += 64;
            }
            return true;
        }

        private void EncryptInternal(byte[] ciphertext, int ciphertextOffset, byte[] message, int messageOffset, int messageLength, byte[] nonce, int nonceOffset)
        {
            Array16<UInt32> internalKey;
            PrepareInternalKey(out internalKey, nonce, nonceOffset);

            Array16<UInt32> temp;
            var tempBytes = new byte[64];//todo: remove allocation
            Array8<UInt32> poly1305Key;

            // first iteration
            {
                SalsaCore.Salsa(out temp, ref internalKey, 20);

                //first half is for Poly1305
                poly1305Key.x0 = temp.x0;
                poly1305Key.x1 = temp.x1;
                poly1305Key.x2 = temp.x2;
                poly1305Key.x3 = temp.x3;
                poly1305Key.x4 = temp.x4;
                poly1305Key.x5 = temp.x5;
                poly1305Key.x6 = temp.x6;
                poly1305Key.x7 = temp.x7;

                // second half for the message
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 0, temp.x8);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 4, temp.x9);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 8, temp.x10);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 12, temp.x11);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 16, temp.x12);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 20, temp.x13);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 24, temp.x14);
                ByteIntegerConverter.StoreLittleEndian32(tempBytes, 28, temp.x15);
                int count = Math.Min(32, messageLength);
                for (int i = 0; i < count; i++)
                    ciphertext[16 + ciphertextOffset + i] = (byte)(message[messageOffset + i] ^ tempBytes[i]);
            }

            // later iterations
            int blockOffset = 32;
            while (blockOffset < messageLength)
            {
                internalKey.x8++;
                SalsaCore.Salsa(out temp, ref internalKey, 20);
                ByteIntegerConverter.Array16StoreLittleEndian32(tempBytes, 0, ref temp);
                int count = Math.Min(64, messageLength - blockOffset);
                for (int i = 0; i < count; i++)
                    ciphertext[16 + ciphertextOffset + blockOffset + i] = (byte)(message[messageOffset + blockOffset + i] ^ tempBytes[i]);
                blockOffset += 64;
            }

            // compute MAC
            Poly1305Donna.poly1305_auth(ciphertext, ciphertextOffset, ciphertext, ciphertextOffset + 16, messageLength, ref poly1305Key);
        }
    }
}
