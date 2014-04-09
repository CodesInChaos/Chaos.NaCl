using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    [TestClass]
    class Poly1305Tests
    {
        [TestMethod]
        public void KeySizeIs32()
        {
            Assert.AreEqual(32, OneTimeAuth.Poly1305.KeySizeInBytes);
        }

        [TestMethod]
        public void SignatureSizeIs16()
        {
            Assert.AreEqual(32, OneTimeAuth.Poly1305.SignatureSizeInBytes);
        }
    }
}
