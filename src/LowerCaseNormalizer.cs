using System;

namespace Korzh.Identity
{
    /// <summary>
    /// Implements <see cref="ILookupNormalizer"/> by converting keys to their lower cased invariant culture representation.
    /// </summary>
    public class LowerInvariantLookupNormalizer : Microsoft.AspNetCore.Identity.ILookupNormalizer
    {
        /// <summary>
        /// Returns a normalized representation of the specified <paramref name="key"/>
        /// by converting keys to their lower cased invariant culture representation.
        /// </summary>
        /// <param name="key">The key to normalize.</param>
        /// <returns>A normalized representation of the specified <paramref name="key"/>.</returns>
        public virtual string Normalize(string key) {
            if (key == null) {
                return null;
            }
            return key.Normalize().ToLowerInvariant();
        }
    }
}
