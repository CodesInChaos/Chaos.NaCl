using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    [TestClass]
    public class Ed25519Tests
    {
        [AssemblyInitializeAttribute]
        public static void LoadTestVectors(TestContext context)
        {
            Ed25519TestVectors.LoadTestCases();
            //Warmup
            var pk = Ed25519.PublicKeyFromSeed(new byte[32]);
            var sk = Ed25519.ExpandedPrivateKeyFromSeed(new byte[32]);
            var sig = Ed25519.Sign(Ed25519TestVectors.TestCases.Last().Message, sk);
            Ed25519.Verify(sig, new byte[10], pk);
        }

        [TestMethod]
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


        [TestMethod]
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

        [TestMethod]
        public void Sign()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var sig = Ed25519.Sign(testCase.Message, testCase.PrivateKey);
                Assert.AreEqual(64, sig.Length);
                TestHelpers.AssertEqualBytes(testCase.Signature, sig);
            }
        }

        [TestMethod]
        public void Verify()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                bool success = Ed25519.Verify(testCase.Signature, testCase.Message, testCase.PublicKey);
                Assert.IsTrue(success);
            }
        }

        [TestMethod]
        public void VerifyFail()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.IsTrue(Ed25519.Verify(signature, message, pk));
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(signature, modifiedMessage, pk));
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(modifiedSignature, message, pk));
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

        // Ed25519 is malleable in the `S` part of the signature
        // One can add (a multiple of) the order of the subgroup `l` to `S` without invalidating the signature
        // I consider rejecting signatures with S >= l
        [TestMethod]
        public void MalleabilityAddL()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.IsTrue(Ed25519.Verify(signature, message, pk));
            var modifiedSignature = signature.Take(32).Concat(AddL(signature.Skip(32))).ToArray();
            Assert.IsTrue(Ed25519.Verify(modifiedSignature, message, pk));
        }

        [TestMethod]
        public void VerifySegments()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                bool success = Ed25519.Verify(testCase.Signature.Pad(), testCase.Message.Pad(), testCase.PublicKey.Pad());
                Assert.IsTrue(success);
            }
        }

        [TestMethod]
        public void VerifyFailSegments()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.IsTrue(Ed25519.Verify(signature.Pad(), message.Pad(), pk.Pad()));
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(signature.Pad(), modifiedMessage.Pad(), pk.Pad()));
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(modifiedSignature.Pad(), message.Pad(), pk.Pad()));
            }
        }

        [TestMethod]
        public void KeyExchange()
        {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] publicKey0, expandedPrivateKey0;
            byte[] seed1 = new byte[32];
            rngCryptoServiceProvider.GetBytes(seed1);
            Ed25519.KeyPairFromSeed(out publicKey0, out expandedPrivateKey0, seed1);
            byte[] publicKey1, expandedPrivateKey1;
            byte[] seed2 = new byte[32];
            rngCryptoServiceProvider.GetBytes(seed2);
            Ed25519.KeyPairFromSeed(out publicKey1, out expandedPrivateKey1, seed2);
            byte[] sharedKey0 = Ed25519.KeyExchange(publicKey1, expandedPrivateKey0);
            byte[] sharedKey1 = Ed25519.KeyExchange(publicKey0, expandedPrivateKey1);
            TestHelpers.AssertEqualBytes(sharedKey0, sharedKey1);
        }
    }
}
