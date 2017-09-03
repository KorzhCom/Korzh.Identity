using System;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Builder;

namespace Microsoft.AspNetCore.Identity {
    /// <summary>
    /// Different extensions which allows to get the values of different claims for some ClaimsPrincipal object
    /// </summary>
    public static class UserClaimsExtensions
    {
        /// <summary>
        /// Gets the first name.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>System.String.</returns>
        public static string GetFirstName(this ClaimsPrincipal principal) {
            return principal.FindFirstValue(ClaimTypes.GivenName);
        }

        /// <summary>
        /// Gets the last name.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>System.String.</returns>
        public static string GetLastName(this ClaimsPrincipal principal) {
            return principal.FindFirstValue(ClaimTypes.Surname);
        }

        /// <summary>
        /// Gets the user identifier.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>System.String.</returns>
        public static string GetUserId(this ClaimsPrincipal principal) {
            return principal.FindFirstValue(ClaimTypes.NameIdentifier);

        }

        /// <summary>
        /// Gets the full name (first name + last name)
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>System.String.</returns>
        public static string GetFullName(this ClaimsPrincipal principal) {
            string fullName = principal.FindFirstValue(ClaimTypes.GivenName);
            string lastName = principal.FindFirstValue(ClaimTypes.Surname);
            if (!string.IsNullOrEmpty(lastName)) {
                if (!string.IsNullOrEmpty(fullName))
                    fullName += " ";
                fullName += lastName;
            }
            return fullName;
        }
    }
}