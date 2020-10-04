using Chaos.NaCl.Internal.Ed25519Ref10;
using Multiformats.Base;
using System.Linq;
using Xunit;

namespace Chaos.NaCl.Tests
{
    public class X25519Tests
    {
        [Fact]
        public void ConvertEd25519ToX25519PrivateKey()
        {
            var edPrivate = Multibase.Base58.Decode("47QbyJEDqmHTzsdg8xzqXD8gqKuLufYRrKWTmB7eAaWHG2EAsQ2GUyqRqWWYT15dGuag52Sf3j4hs2mu7w52mgps");
            const string expected = "96do29HaLryHStVdCD7jB5TdbM1iGwPUDJvnPkfcqhMB";

            var actual = new byte[32];
            MontgomeryCurve25519.EdwardsToMontgomeryPrivate(actual, edPrivate);

            Assert.Equal(expected, Multibase.Base58.Encode(actual));
        }

        [Fact]
        public void ConvertEd25519ToX25519PublicKey()
        {
            var edPublic = Multibase.Base58.Decode("dbDmZLTWuEYYZNHFLKLoRkEX4sZykkSLNQLXvMUyMB1");
            const string expected = "2AbNdSuzFSpGvsiSPBfnamcKzk9Q3WRRpY2EToHZEuKW";

            var actual = new byte[32];
            MontgomeryCurve25519.EdwardsToMontgomery(actual, edPublic);

            Assert.Equal(expected, Multibase.Base58.Encode(actual));
        }

        [Fact]
        public void X25519PublicFromPrivate()
        {
            const string montgomeryPrivate = "96do29HaLryHStVdCD7jB5TdbM1iGwPUDJvnPkfcqhMB";
            const string expectedPublic = "2AbNdSuzFSpGvsiSPBfnamcKzk9Q3WRRpY2EToHZEuKW";

            var actualPublic = MontgomeryCurve25519.GetPublicKey(Multibase.Base58.Decode(montgomeryPrivate));

            Assert.Equal(expectedPublic, Multibase.Base58.Encode(actualPublic));
        }
    }
}
