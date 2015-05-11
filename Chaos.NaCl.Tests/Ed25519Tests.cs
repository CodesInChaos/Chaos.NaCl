using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Chaos.NaCl.Internal.Ed25519Ref10.Ed25519Operations;

namespace Chaos.NaCl.Tests
{

    internal struct TestVectors
    {
        public bool valid;
        public byte[] pub;
        public byte[] repr;
        public byte[] priv;
    };
    

    [TestClass]
    public class Ed25519Tests
    {
        private TestVectors[] vectorz = new[]
        {
            new TestVectors()
            {
                valid = true,
                pub =
                    new byte[]
                    {
                        0x4b, 0x97, 0x97, 0xd0, 0x98, 0x5a, 0xf7, 0x42, 0x9b, 0xc3, 0x55, 0xd9, 0x4, 0x81, 0xcf, 0xc7, 0xcc,
                        0x14, 0x54, 0x5c, 0xa5, 0xe6, 0x7c, 0x84, 0xcb, 0x1b, 0x4a, 0x4c, 0x4d, 0xa1, 0xda, 0x33,
                    },
                repr =
                    new byte[]
                    {
                        0xbc, 0x13, 0x1a, 0x67, 0xb, 0x92, 0x2, 0x65, 0x8f, 0x2f, 0x79, 0xa, 0x7e, 0x4, 0x71, 0xd0, 0xe,
                        0x67, 0x90, 0xdb, 0x4d, 0x59, 0x8, 0xd2, 0x54, 0x4e, 0x5f, 0xbb, 0x8d, 0xa, 0x89, 0x78,
                    },
                priv =
                    new byte[]
                    {
                        0x10, 0x3d, 0xba, 0xb8, 0x6f, 0x99, 0xee, 0xdb, 0xec, 0xa, 0xd6, 0x8f, 0xa9, 0x20, 0x3d, 0x5f, 0xd4,
                        0xf5, 0xe0, 0xdc, 0x48, 0xbc, 0xaf, 0x6c, 0x98, 0x50, 0xd0, 0x1a, 0x12, 0x9f, 0x28, 0x5c,
                    }
            },
            new TestVectors()
            {
                valid = true,
                pub =
                    new byte[]
                    {
                        0xf1, 0x8, 0x6d, 0x75, 0xb3, 0x59, 0x5c, 0xe7, 0x3c, 0x41, 0xa8, 0x11, 0xbf, 0x1a, 0x10, 0xb1, 0xba,
                        0x1a, 0x75, 0xe4, 0xff, 0xd4, 0x98, 0x6c, 0x37, 0x98, 0xe3, 0x54, 0xf3, 0x24, 0x6b, 0x50,
                    },
                repr =
                    new byte[]
                    {
                        0x6, 0x13, 0x6a, 0x4f, 0x20, 0x93, 0x37, 0x12, 0x4f, 0x4d, 0x92, 0x31, 0xc8, 0x34, 0xe9, 0xa0, 0x94,
                        0x8f, 0x89, 0x6d, 0xc9, 0x1c, 0x85, 0x5b, 0x32, 0x80, 0xd3, 0xd1, 0x4f, 0x42, 0xe8, 0x4e,
                    },
                priv =
                    new byte[]
                    {
                        0x68, 0x4f, 0x96, 0xdf, 0xde, 0xa0, 0x57, 0xf5, 0xb2, 0x3f, 0xf6, 0x29, 0x52, 0xb3, 0x34, 0x95,
                        0xb0, 0x7b, 0xa3, 0xd5, 0x4, 0xac, 0x79, 0x1d, 0xf, 0x3c, 0x87, 0x52, 0x3a, 0xa7, 0x3f, 0x6d,
                    }
            },
            new TestVectors()
            {
                valid = true,
                pub =
                    new byte[]
                    {
                        0x49, 0x76, 0xe, 0x1, 0x60, 0x24, 0x44, 0x48, 0x48, 0xc7, 0x9d, 0xc1, 0x81, 0x4, 0x6d, 0xc, 0x3a,
                        0x48, 0x8e, 0xf8, 0x67, 0xbd, 0xf9, 0xd1, 0x6f, 0x8c, 0x8f, 0xe4, 0x9b, 0x7b, 0x7f, 0x66,
                    },
                repr =
                    new byte[]
                    {
                        0xb7, 0xdd, 0x0, 0x28, 0x3, 0xe0, 0x9f, 0x93, 0x52, 0x5d, 0xf6, 0x49, 0xa3, 0x9, 0xbf, 0x29, 0x16,
                        0x71, 0xfd, 0x82, 0x52, 0x23, 0xf2, 0x96, 0x2, 0xee, 0x97, 0x20, 0xc1, 0xd7, 0xa6, 0x3b,
                    },
                priv =
                    new byte[]
                    {
                        0x8, 0x69, 0x14, 0xc7, 0xc7, 0xe8, 0x33, 0x79, 0x27, 0xf4, 0xa7, 0x1c, 0xda, 0x21, 0x25, 0x41, 0x9a,
                        0xe7, 0xe1, 0x83, 0x90, 0x52, 0x1f, 0xaf, 0x14, 0x3d, 0x5a, 0x2, 0xbc, 0x2e, 0x9c, 0x55,
                    }
            },
            new TestVectors()
            {
                valid = false,
                pub =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                repr =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                priv =
                    new byte[]
                    {
                        0x78, 0x51, 0x2b, 0xcf, 0xe1, 0x62, 0x1d, 0x53, 0xed, 0xfc, 0xd5, 0xc0, 0x96, 0xc8, 0xb9, 0x96,
                        0x8e, 0x3, 0x7, 0x5e, 0xc3, 0x3a, 0x2e, 0xea, 0xaa, 0x44, 0x96, 0x64, 0x71, 0xfc, 0x98, 0x65,
                    }
            },
            new TestVectors()
            {
                valid = false,
                pub =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                repr =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                priv =
                    new byte[]
                    {
                        0x38, 0xa9, 0xb4, 0x8a, 0xe8, 0x8b, 0xad, 0xbe, 0x15, 0xd9, 0xbe, 0x6b, 0x1d, 0xf8, 0x82, 0xa1,
                        0x89, 0x60, 0xd1, 0x14, 0xb6, 0x74, 0xba, 0xe8, 0x3f, 0xb6, 0xac, 0xd4, 0x5d, 0x94, 0x1, 0x68,
                    }
            },
            new TestVectors()
            {
                valid = true,
                pub =
                    new byte[]
                    {
                        0x1e, 0x92, 0x62, 0xd, 0xc3, 0x9f, 0xf1, 0x28, 0x86, 0x40, 0x80, 0xb1, 0xfd, 0x37, 0xb9, 0x91, 0xac,
                        0xcc, 0xbf, 0x3d, 0x2e, 0x48, 0x67, 0xd2, 0xed, 0xf1, 0x75, 0xa6, 0x58, 0x10, 0x6d, 0x55,
                    },
                repr =
                    new byte[]
                    {
                        0x5a, 0x25, 0x9d, 0x71, 0x1f, 0xec, 0xb2, 0x6d, 0xe7, 0x8, 0x4f, 0x8d, 0x80, 0x15, 0x4e, 0xec, 0x8c,
                        0xa3, 0xde, 0xd5, 0xde, 0x3f, 0xb6, 0x2f, 0x38, 0xc8, 0x6b, 0xf5, 0xf6, 0x84, 0x6e, 0x26,
                    },
                priv =
                    new byte[]
                    {
                        0x28, 0x4f, 0x7, 0xcf, 0x45, 0xc0, 0x56, 0x74, 0xc6, 0xa7, 0xce, 0xa4, 0x8e, 0xf1, 0x83, 0xb7, 0xb5,
                        0x22, 0x3c, 0xff, 0xe9, 0x2e, 0xa7, 0xcb, 0x78, 0xa2, 0x3, 0x1a, 0x47, 0x54, 0xc, 0x6d,
                    }
            },
            new TestVectors()
            {
                valid = false,
                pub =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                repr =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                priv =
                    new byte[]
                    {
                        0x10, 0x22, 0xe3, 0x43, 0x94, 0x95, 0xd7, 0xd9, 0x0, 0xf5, 0xf5, 0xac, 0xd, 0x39, 0x6, 0x48, 0x86,
                        0x54, 0x91, 0xe2, 0x88, 0xe5, 0xc2, 0xe6, 0x53, 0x5f, 0x10, 0xd8, 0x3e, 0xd0, 0xe, 0x7f,
                    }
            },
            new TestVectors()
            {
                valid = false,
                pub =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                repr =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                priv =
                    new byte[]
                    {
                        0xa8, 0x30, 0x33, 0xe7, 0x55, 0x18, 0xae, 0x32, 0xb2, 0xd4, 0xdd, 0xb7, 0x76, 0x9a, 0x73, 0xd7,
                        0x72, 0x8d, 0x5f, 0xd8, 0xd8, 0xe9, 0x57, 0x8a, 0xa9, 0x8e, 0xb6, 0x12, 0x7b, 0x3e, 0x8d, 0x6e,
                    }
            },
            new TestVectors()
            {
                valid = true,
                pub =
                    new byte[]
                    {
                        0x64, 0x27, 0xe0, 0x5, 0x13, 0xab, 0x7a, 0x81, 0x46, 0xd5, 0x8e, 0xbc, 0x28, 0x25, 0xf4, 0x66, 0xe3,
                        0x1c, 0x12, 0xbf, 0x97, 0x25, 0x99, 0x20, 0x37, 0x27, 0xd6, 0x1e, 0x9b, 0x6a, 0x6e, 0x7d,
                    },
                repr =
                    new byte[]
                    {
                        0x5f, 0x9e, 0x2, 0x23, 0x7c, 0xa4, 0xfc, 0xc2, 0xc1, 0x8c, 0xc8, 0x91, 0x53, 0xdb, 0xa7, 0x5c, 0xca,
                        0x58, 0xea, 0x12, 0x60, 0x41, 0x3f, 0x36, 0xe, 0xe7, 0x7d, 0x78, 0x1d, 0x72, 0xa9, 0x33,
                    },
                priv =
                    new byte[]
                    {
                        0x80, 0x5a, 0x8f, 0xba, 0x73, 0x45, 0x30, 0xc8, 0xf0, 0xb7, 0x64, 0x6a, 0xae, 0x73, 0x6f, 0x54,
                        0x65, 0x22, 0x5, 0xe8, 0x7, 0xd6, 0xab, 0x83, 0xc2, 0xe6, 0x79, 0x5e, 0x9a, 0x73, 0x22, 0x78,
                    }
            },
            new TestVectors()
            {
                valid = false,
                pub =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                repr =
                    new byte[]
                    {
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    },
                priv =
                    new byte[]
                    {
                        0xc8, 0x25, 0x50, 0x29, 0xcd, 0x16, 0x69, 0xa9, 0x5c, 0x37, 0xab, 0xe7, 0xf5, 0x51, 0x9e, 0xaa,
                        0xbe, 0x7e, 0x8d, 0x51, 0x27, 0x4c, 0xd4, 0x46, 0x14, 0xb, 0xf9, 0x50, 0x80, 0x4, 0x14, 0x6e,
                    }
            }
        };




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
        public void ElligatorTest()
        {
            var rnd = new RNGCryptoServiceProvider();
            for (var i = 0; i< 100000; i++)
            {
                var publicKey1= new byte[32];
                var publicKey2= new byte[32];
                var publicKey3 = new byte[32];
                var privateKey = new byte[32];
                var rep = new byte[32];

                rnd.GetBytes(privateKey);

                if (Elligator(publicKey1, rep, privateKey))
                {
                    RepresentativeToPublicKey(rep, publicKey2);
                    crypto_ecdh_keypair(publicKey3, privateKey);
                    TestHelpers.AssertEqualBytes(publicKey2, publicKey3);
                    TestHelpers.AssertEqualBytes(publicKey2, publicKey1);
                }
                
            }



            var representative1 = new byte[32];
            var decodedPubKey1 = new byte[32];
            var publicKeyT1 = new byte[32];
            var res1 = Elligator(publicKeyT1, representative1, vectorz[0].priv);


            var representative2 = new byte[32];
            var decodedPubKey2 = new byte[32];
            var publicKeyT2 = new byte[32];
            var res2 = Elligator(publicKeyT2, representative2, vectorz[1].priv);

            var k1 = MontgomeryCurve25519.KeyExchange(publicKeyT1, vectorz[1].priv);
            var k2 = MontgomeryCurve25519.KeyExchange(publicKeyT2, vectorz[0].priv);


            foreach (var vector in vectorz)
            {
                var representative = new byte[32];
                var decodedPubKey = new byte[32];
                var publicKeyT = new byte[32];
                var res = Elligator(publicKeyT, representative, vector.priv);
                Assert.AreEqual(res, vector.valid);
                if (res)
                {
                    RepresentativeToPublicKey(representative, decodedPubKey);
                    TestHelpers.AssertEqualBytes(decodedPubKey, vector.pub);
                }
            }
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
        [TestMethod]
        public void MalleabilityAddL()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.IsTrue(Ed25519.Verify(signature, message, pk));
            var modifiedSignature = AddLToSignature(signature);
            Assert.IsTrue(Ed25519.Verify(modifiedSignature, message, pk));
            var modifiedSignature2 = AddLToSignature(modifiedSignature);
            Assert.IsFalse(Ed25519.Verify(modifiedSignature2, message, pk));
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
            var seed = new byte[32];

            byte[] publicEdwards, privateEdwards;
            Ed25519.KeyPairFromSeed(out publicEdwards, out privateEdwards, seed);
            var sharedEdwards = Ed25519.KeyExchange(publicEdwards, privateEdwards);

            var privateMontgomery = Sha512.Hash(seed).Take(32).ToArray();
            var publicMontgomery = MontgomeryCurve25519.GetPublicKey(privateMontgomery);
            var sharedMontgomery = MontgomeryCurve25519.KeyExchange(publicMontgomery, privateMontgomery);

            TestHelpers.AssertEqualBytes(sharedMontgomery, sharedEdwards);
        }

        [TestMethod]
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
