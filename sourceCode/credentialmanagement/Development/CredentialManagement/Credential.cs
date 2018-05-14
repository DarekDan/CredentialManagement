using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Text;

namespace CredentialManagement
{
    public class Credential: IDisposable
    {
        private const string PasswordExceeded512Bytes = "The password has exceeded 512 bytes.";
        static readonly object LockObject = new object();
        bool _disposed;

        static readonly SecurityPermission UnmanagedCodePermission;

        CredentialType _type;
        string _target;
        SecureString _password;
        string _username;
        string _description;
        DateTime _lastWriteTime;
        PersistanceType _persistenceType;

        static Credential()
        {
            lock (LockObject)
            {
                UnmanagedCodePermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
            }
        }
        public Credential()
            : this(null)
        {
        }

        public Credential(string username)
            : this(username, null)
        {
        }

        public Credential(string username, string password)
            : this(username, password, null)
        {
        }

        public Credential(string username, string password, string target)
            : this(username, password, target, CredentialType.Generic)
        {
        }

        public Credential(string username, string password, string target, CredentialType type)
        {
            Username = username;
            Password = password;
            Target = target;
            Type = type;
            PersistenceType = PersistanceType.Session;
            _lastWriteTime = DateTime.MinValue;
        }


        public void Dispose()
        {
            Dispose(true);

            // Prevent GC Collection since we have already disposed of this object
            GC.SuppressFinalize(this);
        }
        ~Credential()
        {
            Dispose(false);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    SecurePassword.Clear();
                    SecurePassword.Dispose();
                }
            }
            _disposed = true;
        }

        private void CheckNotDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("Credential object is already disposed.");
            }
        }


        public string Username {
            get
            {
                CheckNotDisposed();
                return _username;
            }
            set
            {
                CheckNotDisposed();
                _username = value;
            }
        }
        public string Password
        {
            get => SecureStringHelper.CreateString(SecurePassword);
            set
            {
                CheckNotDisposed();
                SecurePassword = SecureStringHelper.CreateSecureString(value);
            }
        }
        public SecureString SecurePassword
        {
            get
            {
                CheckNotDisposed();
                UnmanagedCodePermission.Demand();
                return null == _password ? new SecureString() : _password.Copy();
            }
            set
            {
                CheckNotDisposed();
                if (null != _password)
                {
                    _password.Clear();
                    _password.Dispose();
                }
                _password = null == value ? new SecureString() : value.Copy();
            }
        }
        public string Target
        {
            get
            {
                CheckNotDisposed();
                return _target;
            }
            set
            {
                CheckNotDisposed();
                _target = value;
            }
        }

        public string Description
        {
            get
            {
                CheckNotDisposed();
                return _description;
            }
            set
            {
                CheckNotDisposed();
                _description = value;
            }
        }

        public DateTime LastWriteTime => LastWriteTimeUtc.ToLocalTime();

        public DateTime LastWriteTimeUtc 
        { 
            get
            {
                CheckNotDisposed();
                return _lastWriteTime;
            }
            private set => _lastWriteTime = value;
        }

        public CredentialType Type
        {
            get
            {
                CheckNotDisposed();
                return _type;
            }
            set
            {
                CheckNotDisposed();
                _type = value;
            }
        }

        public PersistanceType PersistenceType
        {
            get
            {
                CheckNotDisposed();
                return _persistenceType;
            }
            set
            {
                CheckNotDisposed();
                _persistenceType = value;
            }
        }

        public bool Save()
        {
            CheckNotDisposed();
            UnmanagedCodePermission.Demand();

            byte[] passwordBytes = Encoding.Unicode.GetBytes(Password);
            if (Password.Length > (512))
            {
                throw new ArgumentOutOfRangeException(PasswordExceeded512Bytes);
            }

            NativeMethods.CREDENTIAL credential = new NativeMethods.CREDENTIAL();
            credential.TargetName = Target;
            credential.UserName = Username;
            credential.CredentialBlob = Marshal.StringToCoTaskMemUni(Password);
            credential.CredentialBlobSize = passwordBytes.Length;
            credential.Comment = Description;
            credential.Type = (int)Type;
            credential.Persist = (int) PersistenceType;

            bool result = NativeMethods.CredWrite(ref credential, 0);
            if (!result)
            {
                return false;
            }
            LastWriteTimeUtc = DateTime.UtcNow;
            return true;
        }

        public bool Delete()
        {
            CheckNotDisposed();
            UnmanagedCodePermission.Demand();

            if (string.IsNullOrEmpty(Target))
            {
                throw new InvalidOperationException("Target must be specified to delete a credential.");
            }

            StringBuilder target = string.IsNullOrEmpty(Target) ? new StringBuilder() : new StringBuilder(Target);
            bool result = NativeMethods.CredDelete(target, Type, 0);
            return result;
        }

        public bool Load()
        {
            CheckNotDisposed();
            UnmanagedCodePermission.Demand();

            IntPtr credPointer;

            bool result = NativeMethods.CredRead(Target, Type, 0, out credPointer);
            if (!result)
            {
                return false;
            }
            using (NativeMethods.CriticalCredentialHandle credentialHandle = new NativeMethods.CriticalCredentialHandle(credPointer))
            {
                LoadInternal(credentialHandle.GetCredential());
            }
            return true;
        }

        public bool Exists()
        {
            CheckNotDisposed();
            UnmanagedCodePermission.Demand();

            if (string.IsNullOrEmpty(Target))
            {
                throw new InvalidOperationException("Target must be specified to check existance of a credential.");
            }

            using (Credential existing = new Credential { Target = Target, Type = Type })
            {
                return existing.Load();
            }
        }

        internal void LoadInternal(NativeMethods.CREDENTIAL credential)
        {
            Username = credential.UserName;
            if (credential.CredentialBlobSize > 0)
            {
                Password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
            }
            Target = credential.TargetName;
            Type = (CredentialType)credential.Type;
            PersistenceType = (PersistanceType)credential.Persist;
            Description = credential.Comment;
            LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten);
        }
    }
}