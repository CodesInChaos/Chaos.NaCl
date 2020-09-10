using System;
using System.Collections.Generic;
using System.Linq;
using Chaos.NaCl.Internal;
using Xunit;

namespace Chaos.NaCl.Tests
{
    
    public class InternalAssertTests
    {
        [Fact]
        public void AssertSuccess()
        {
            InternalAssert.Assert(true, "a");
        }

        [Fact]
        public void AssertFail()
        {
            Assert.Throws<InvalidOperationException>(() => InternalAssert.Assert(false, "a"));
        }
    }
}
