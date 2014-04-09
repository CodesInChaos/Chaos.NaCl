using System;
using System.Collections.Generic;
using System.Linq;
using Chaos.NaCl.Internal;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    [TestClass]
    public class InternalAssertTests
    {
        [TestMethod]
        public void AssertSuccess()
        {
            InternalAssert.Assert(true, "a");
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void AssertFail()
        {
            InternalAssert.Assert(false, "a");
        }
    }
}
