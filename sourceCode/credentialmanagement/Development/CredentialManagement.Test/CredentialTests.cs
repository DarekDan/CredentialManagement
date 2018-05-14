using System;
using NUnit.Framework;

namespace CredentialManagement.Test
{
    [TestFixture]
    public class CredentialTests
    {
        [Test]
        public void Credential_Create_ShouldNotThrowNull()
        {
            Assert.NotNull(new Credential());
        }

        [Test]
        public void Credential_Create_With_Username_ShouldNotThrowNull()
        {
            Assert.NotNull(new Credential("username"));
        }

        [Test]
        public void Credential_Create_With_Username_And_Password_ShouldNotThrowNull()
        {
            Assert.NotNull(new Credential("username", "password"));
        }
        [Test]
        public void Credential_Create_With_Username_Password_Target_ShouldNotThrowNull()
        {
            Assert.NotNull(new Credential("username", "password","target"));
        }

        [Test]
        public void Credential_ShouldBe_IDisposable()
        {
            var disposable = new Credential() as IDisposable;
            Assert.IsNotNull(disposable, "Credential should implement IDisposable Interface.");
        }
        
        [Test]
        public void Credential_Dispose_ShouldNotThrowException()
        {
            new Credential().Dispose();
        }

        [Test]
        public void Credential_ShouldThrowObjectDisposedException()
        {
            Credential disposed = new Credential {Password = "password"};
            disposed.Dispose();
            Assert.Throws(typeof(ObjectDisposedException), () => disposed.Username = "username" );
        }

        [Test]
        public void Credential_Save()
        {
            Credential saved =
                new Credential("username", "password", "target", CredentialType.Generic)
                {
                    PersistanceType = PersistanceType.LocalComputer
                };
            var result = saved.Save();
            Assert.IsTrue(result);
        }
        
        [Test]
        public void Credential_Delete()
        {
            new Credential("username", "password", "target").Save();
            var result = new Credential("username", "password","target").Delete();
            Assert.IsTrue(result);
        }

        [Test]
        public void Credential_Delete_NullTerminator()
        {
            Credential credential =
                new Credential(null, null, "\0", CredentialType.None) {Description = null};
            var result = credential.Delete();
            Assert.IsFalse(result);
        }
       
        [Test]
        public void Credential_Load()
        {
            Credential setup = new Credential("username", "password", "target", CredentialType.Generic);
            setup.Save();

            Credential credential = new Credential {Target = "target", Type = CredentialType.Generic };
            var result = credential.Load();
            Assert.That(result, Is.True);

            Assert.IsNotNull(credential.Username);
            Assert.IsNotNull(credential.Password);
            Assert.AreEqual(credential.Username,"username");
            Assert.AreEqual(credential.Password,"password");
            Assert.AreEqual(credential.Target,"target");
        }

        [Test]
        public void Credential_Exists_Target_ShouldNotBeNull()
        {
            new Credential { Username = "username", Password = "password", Target = "target" }.Save();
            
            Credential existingCred = new Credential {Target = "target"};
            Assert.True(existingCred.Exists());
            
            existingCred.Delete();
        }
    }
}
