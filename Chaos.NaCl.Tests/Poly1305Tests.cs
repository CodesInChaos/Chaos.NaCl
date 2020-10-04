using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Chaos.NaCl.Tests
{
    
    public class Poly1305Tests
    {
        [Fact]
        public void KeySizeIs32()
        {
            Assert.Equal(32, OneTimeAuth.Poly1305.KeySizeInBytes);
        }

        [Fact]
        public void SignatureSizeIs16()
        {
            Assert.Equal(16, OneTimeAuth.Poly1305.SignatureSizeInBytes);
        }
    }
}
