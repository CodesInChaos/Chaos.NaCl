﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Xunit;

namespace Chaos.NaCl.Tests
{
    public class Ed25519Tests
    {
        [Fact]
        public void KeyPairFromSeed()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                byte[] publicKey;
                byte[] privateKey;
                Ed25519.KeyPairFromSeed(out publicKey, out privateKey, testCase.Seed);
                TestHelpers.AssertEqualBytes(testCase.PublicKey, publicKey);
                TestHelpers.AssertEqualBytes(testCase.PrivateKey, privateKey);
            }
        }


        [Fact]
        public void KeyPairFromSeedSegments()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var publicKey = new byte[Ed25519.PublicKeySizeInBytes].Pad();
                var privateKey = new byte[Ed25519.ExpandedPrivateKeySizeInBytes].Pad();
                Ed25519.KeyPairFromSeed(publicKey, privateKey, testCase.Seed.Pad());
                TestHelpers.AssertEqualBytes(testCase.PublicKey, publicKey.UnPad());
                TestHelpers.AssertEqualBytes(testCase.PrivateKey, privateKey.UnPad());
            }
        }

        [Fact]
        public void Sign()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var sig = Ed25519.Sign(testCase.Message, testCase.PrivateKey);
                Assert.Equal(64, sig.Length);
                TestHelpers.AssertEqualBytes(testCase.Signature, sig);
            }
        }

        [Fact]
        public void Verify()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                bool success = Ed25519.Verify(testCase.Signature, testCase.Message, testCase.PublicKey);
                Assert.True(success);
            }
        }

        [Fact]
        public void VerifyFail()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.True(Ed25519.Verify(signature, message, pk));
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Assert.False(Ed25519.Verify(signature, modifiedMessage, pk));
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Assert.False(Ed25519.Verify(modifiedSignature, message, pk));
            }
        }

        private byte[] AddL(IEnumerable<byte> input)
        {
            var signedInput = input.Concat(new byte[] { 0 }).ToArray();
            var i = new BigInteger(signedInput);
            var l = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
            i += l;
            var result = i.ToByteArray().Concat(Enumerable.Repeat((byte)0, 32)).Take(32).ToArray();
            return result;
        }

        private byte[] AddLToSignature(byte[] signature)
        {
            return signature.Take(32).Concat(AddL(signature.Skip(32))).ToArray();
        }

        // Ed25519 is malleable in the `S` part of the signature
        // One can add (a multiple of) the order of the subgroup `l` to `S` without invalidating the signature
        // The implementation only checks if the 3 high bits are zero, which is equivalent to checking if S < 2^253
        // since `l` is only slightly larger than 2^252 this means that you can add `l` to almost every signature
        // *once* without violating this condition, adding it twice will exceed 2^253 causing the signature to be rejected
        // This test serves to document the *is* behaviour, and doesn't define *should* behaviour
        //
        // I consider rejecting signatures with S >= l, but should probably talk to upstream and libsodium before that
        [Fact]
        public void MalleabilityAddL()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.True(Ed25519.Verify(signature, message, pk));
            var modifiedSignature = AddLToSignature(signature);
            Assert.True(Ed25519.Verify(modifiedSignature, message, pk));
            var modifiedSignature2 = AddLToSignature(modifiedSignature);
            Assert.False(Ed25519.Verify(modifiedSignature2, message, pk));
        }

        [Fact]
        public void VerifySegments()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                bool success = Ed25519.Verify(testCase.Signature.Pad(), testCase.Message.Pad(), testCase.PublicKey.Pad());
                Assert.True(success);
            }
        }

        [Fact]
        public void VerifyFailSegments()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.True(Ed25519.Verify(signature.Pad(), message.Pad(), pk.Pad()));
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Assert.False(Ed25519.Verify(signature.Pad(), modifiedMessage.Pad(), pk.Pad()));
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Assert.False(Ed25519.Verify(modifiedSignature.Pad(), message.Pad(), pk.Pad()));
            }
        }

        [Fact]
        public void KeyExchange()
        {
            var seed = new byte[32];

            byte[] publicEdwards, privateEdwards;
            Ed25519.KeyPairFromSeed(out publicEdwards, out privateEdwards, seed);
            var sharedEdwards = Ed25519.KeyExchange(publicEdwards, privateEdwards);

            var privateMontgomery = Sha512.Hash(seed).Take(32).ToArray();
            var publicMontgomery = MontgomeryCurve25519.GetPublicKey(privateMontgomery);
            var sharedMontgomery = MontgomeryCurve25519.KeyExchange(publicMontgomery, privateMontgomery);

            TestHelpers.AssertEqualBytes(sharedMontgomery, sharedEdwards);
        }

        [Fact]
        public void KeyExchangeSegments()
        {
            var seed = new byte[32].Pad();

            var publicEdwards = new byte[32].Pad();
            var privateEdwards = new byte[64].Pad();
            Ed25519.KeyPairFromSeed(publicEdwards, privateEdwards, seed);
            var sharedEdwards = new byte[32].Pad();
            Ed25519.KeyExchange(sharedEdwards, publicEdwards, privateEdwards);

            var privateMontgomery = Sha512.Hash(seed.UnPad()).Take(32).ToArray();
            var publicMontgomery = MontgomeryCurve25519.GetPublicKey(privateMontgomery);
            var sharedMontgomery = MontgomeryCurve25519.KeyExchange(publicMontgomery, privateMontgomery);

            TestHelpers.AssertEqualBytes(sharedMontgomery, sharedEdwards.UnPad());
        }

    }
}
