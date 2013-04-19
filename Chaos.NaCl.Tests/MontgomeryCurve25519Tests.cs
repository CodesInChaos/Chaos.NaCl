using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
	[TestClass]
	public class MontgomeryCurve25519Tests
	{
		[TestMethod]
		public void GetPublicKey_Alice()
		{
			var calculatedAlicePublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.AlicePrivateKey);
			Assert.IsTrue(MontgomeryCurve25519TestVectors.AlicePublicKey.SequenceEqual(calculatedAlicePublicKey));
		}

		[TestMethod]
		public void GetPublicKey_Bob()
		{
			var calculatedBobPublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.BobPrivateKey);
			Assert.IsTrue(MontgomeryCurve25519TestVectors.BobPublicKey.SequenceEqual(calculatedBobPublicKey));
		}

		[TestMethod]
		public void GetSharedKey_AliceBob()
		{
			var calculatedSharedAlice = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.BobPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
			Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceBobSharedKey), BitConverter.ToString(calculatedSharedAlice));
		}

		[TestMethod]
		public void GetSharedKey_AliceFrank0()
		{
			var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey0, MontgomeryCurve25519TestVectors.AlicePrivateKey);
			Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceFrankSharedKey), BitConverter.ToString(calculatedSharedAliceFrank));
		}

		[TestMethod]
		public void GetSharedKey_AliceFrank()
		{
			var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
			Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceFrankSharedKey), BitConverter.ToString(calculatedSharedAliceFrank));
		}


		[TestMethod]
		public void GetSharedKey_BobAlice()
		{
			var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
			Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceBobSharedKey), BitConverter.ToString(calculatedSharedBob));
		}

		[TestMethod]
		public void GetSharedKey_BobFrank()
		{
			var calculatedSharedBobFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
			Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.BobFrankSharedKey), BitConverter.ToString(calculatedSharedBobFrank));
		}

		[TestMethod]
		public void GetSharedKey_BobAlice2()
		{
			var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey2, MontgomeryCurve25519TestVectors.BobPrivateKey);
			Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceBobSharedKey), BitConverter.ToString(calculatedSharedBob));
		}

		public MontgomeryCurve25519Tests()
		{
			//Warmup
			MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.AlicePrivateKey);
			MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
			MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.BobPublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
		}
	}
}
