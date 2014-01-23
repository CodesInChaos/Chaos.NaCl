using System;
using System.Linq;
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
				Assert.AreEqual(BitConverter.ToString(testCase.PublicKey), BitConverter.ToString(publicKey));
				Assert.AreEqual(BitConverter.ToString(testCase.PrivateKey), BitConverter.ToString(privateKey));
			}
		}

		[TestMethod]
		public void Sign()
		{
			foreach (var testCase in Ed25519TestVectors.TestCases)
			{
				var sig = Ed25519.Sign(testCase.Message, testCase.PrivateKey);
				Assert.AreEqual(64, sig.Length);
				Assert.AreEqual(BitConverter.ToString(testCase.Signature), BitConverter.ToString(sig));
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
	}
}
