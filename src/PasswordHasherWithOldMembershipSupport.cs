using System;
using System.Text;
using System.Security.Cryptography;

using Microsoft.AspNetCore.Identity;


namespace Korzh.Identity
{
    /// <summary>
    /// Represents IPasswordHasher implementation which accepts the hashes from old ASP.NET Membership library
    /// </summary>
    /// <typeparam name="TUser">The type which represents user model class.</typeparam>
    /// <seealso cref="Microsoft.AspNetCore.Identity.IPasswordHasher{TUser}" />
    public class PasswordHasherWithOldMembershipSupport<TUser> : IPasswordHasher<TUser> where TUser : class
    {

        IPasswordHasher<TUser> _identityPasswordHasher = new Microsoft.AspNetCore.Identity.PasswordHasher<TUser>();

        /// <summary>
        /// Hashes the password in old (ASP.NET Membership) format.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <returns>System.String.</returns>
        internal static string HashPasswordInOldFormat(string password) {
            var sha1 = new SHA1CryptoServiceProvider();
            var data = Encoding.ASCII.GetBytes(password);
            var sha1data = sha1.ComputeHash(data);
            return Convert.ToBase64String(sha1data);
        }


        /// <summary>
        /// Returns a hashed representation of the supplied <paramref name="password" /> for the specified <paramref name="user" />.
        /// This function always uses the new hashing algorithm (from ASP.NET Core Identity library)
        /// </summary>
        /// <param name="user">The user whose password is to be hashed.</param>
        /// <param name="password">The password to hash.</param>
        /// <returns>A hashed representation of the supplied <paramref name="password" /> for the specified <paramref name="user" />.</returns>
        public string HashPassword(TUser user, string password) {
            return _identityPasswordHasher.HashPassword(user, password);
        }

        /// <summary>
        /// Returns a <see cref="T:Microsoft.AspNetCore.Identity.PasswordVerificationResult" /> indicating the result of a password hash comparison.
        /// This function first tries to verify the password using the old format and then (if it fails) passes it to the base verification function.
        /// So both the password hashes in old and new formats will be verified correctly
        /// </summary>
        /// <param name="user">The user whose password should be verified.</param>
        /// <param name="hashedPassword">The hash value for a user's stored password.</param>
        /// <param name="providedPassword">The password supplied for comparison.</param>
        /// <returns>A <see cref="T:Microsoft.AspNetCore.Identity.PasswordVerificationResult" /> indicating the result of a password hash comparison.</returns>
        /// <remarks>Implementations of this method should be time consistent.</remarks>
        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword) {
            string pwdHash2 = HashPasswordInOldFormat(providedPassword);
            if (hashedPassword == pwdHash2)
                return PasswordVerificationResult.Success;
            else
                return _identityPasswordHasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
    }

}
