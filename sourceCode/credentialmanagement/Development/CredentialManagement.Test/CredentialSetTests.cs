﻿using System;
using System.Linq;
using NUnit.Framework;

namespace CredentialManagement.Test
{
    [TestFixture]
    public class CredentialSetTests
    {
        [Test]
        public void CredentialSet_Create()
        {
            Assert.IsNotNull(new CredentialSet());
        }

        [Test]
        public void CredentialSet_Create_WithTarget()
        {
            Assert.IsNotNull(new CredentialSet("target"));
        }

        [Test]
        public void CredentialSet_ShouldBeIDisposable()
        {
            var disposable = new CredentialSet() as IDisposable;
            Assert.IsNotNull(disposable, "CredentialSet needs to implement IDisposable Interface.");
        }

        [Test]
        public void CredentialSet_Load()
        {
            Credential credential = new Credential
                                        {
                                            Username = "username",
                                            Password = "password",
                                            Target = "target",
                                            Type = CredentialType.Generic
                                        };
            credential.Save();

            CredentialSet set = new CredentialSet();
            set.Load();
            Assert.IsTrue(set != null && set.Any());            
            credential.Delete();

            set.Dispose();
        }

        [Test]
        public void CredentialSet_Load_ShouldReturn_Self()
        {
            CredentialSet set = new CredentialSet();
            object result = set.Load();
            Assert.IsInstanceOf(typeof(CredentialSet),result);

            set.Dispose();
        }

        [Test]
        public void CredentialSet_Load_With_TargetFilter()
        {
            Credential credential = new Credential
                                        {
                                            Username = "filteruser",
                                            Password = "filterpassword",
                                            Target = "filtertarget"
                                        };
            credential.Save();

            CredentialSet set = new CredentialSet("filtertarget");
            var result = set.Load();
            Assert.AreEqual(result.Count,1);
            set.Dispose();
        }
    }
}
