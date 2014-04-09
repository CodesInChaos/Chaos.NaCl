using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    [TestClass]
    public class MontgomeryCurve25519Tests
    {
        [TestMethod]
        public void GetPublicKeyAlice()
        {
            var calculatedAlicePublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.AlicePrivateKey);
            Assert.IsTrue(MontgomeryCurve25519TestVectors.AlicePublicKey.SequenceEqual(calculatedAlicePublicKey));
        }

        [TestMethod]
        public void GetPublicKeyBob()
        {
            var calculatedBobPublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.BobPrivateKey);
            Assert.IsTrue(MontgomeryCurve25519TestVectors.BobPublicKey.SequenceEqual(calculatedBobPublicKey));
        }

        [TestMethod]
        public void GetPublicKeySegments()
        {
            var privateKey = MontgomeryCurve25519TestVectors.BobPrivateKey.Pad();
            var calculatedBobPublicKey = new byte[32].Pad();
            MontgomeryCurve25519.GetPublicKey(calculatedBobPublicKey, privateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.BobPublicKey, calculatedBobPublicKey.UnPad());
        }

        [TestMethod]
        public void GetSharedKeySegments()
        {
            var bobPublic = MontgomeryCurve25519TestVectors.BobPublicKey.Pad();
            var alicePrivate = MontgomeryCurve25519TestVectors.AlicePrivateKey.Pad();
            var calculatedSharedAlice = new byte[32].Pad();
            MontgomeryCurve25519.KeyExchange(calculatedSharedAlice, bobPublic, alicePrivate);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedAlice.UnPad());
        }

        [TestMethod]
        public void GetSharedKeyAliceBob()
        {
            var calculatedSharedAlice = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.BobPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedAlice);
        }

        [TestMethod]
        public void GetSharedKeyAliceFrank0()
        {
            var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey0, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceFrankSharedKey, calculatedSharedAliceFrank);
        }

        [TestMethod]
        public void GetSharedKeyAliceFrank()
        {
            var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceFrankSharedKey, calculatedSharedAliceFrank);
        }


        [TestMethod]
        public void GetSharedKeyBobAlice()
        {
            var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedBob);
        }

        [TestMethod]
        public void GetSharedKeyBobFrank()
        {
            var calculatedSharedBobFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.BobFrankSharedKey, calculatedSharedBobFrank);
        }

        [TestMethod]
        public void GetSharedKeyBobAlice2()
        {
            var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey2, MontgomeryCurve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedBob);
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
