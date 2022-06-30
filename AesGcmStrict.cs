using System;
using System.Security.Cryptography;

namespace SecurityDriven
{
	/// <summary>
	/// Enforces AesGcm Tag to be exactly 16 bytes.
	/// Use instead of AesGcm class, which allows truncated Tags (ex. any AesGcm-provided Tag truncated to 12 bytes will successfully decrypt).
	/// </summary>
	public sealed class AesGcmStrict : IDisposable
	{
		readonly AesGcm _aesGcm;

		const int FIXED_TAG_LENGTH = 16;
		const string FIXED_TAG_LENGTH_STRING = "16";

#if NET6_0_OR_GREATER
		/// <summary>Gets a value that indicates whether the algorithm is supported on the current platform.</summary>
		public static bool IsSupported => AesGcm.IsSupported;
#endif
		/// <summary>Gets a value that indicates whether the algorithm is supported on the current platform.</summary>
		public static KeySizes NonceByteSizes { get; } = AesGcm.NonceByteSizes;

		/// <summary>Gets the tag sizes, in bytes, supported by this instance.</summary>
		public static KeySizes TagByteSizes { get; } = new KeySizes(FIXED_TAG_LENGTH, FIXED_TAG_LENGTH, 1);

		/// <summary>Initializes a new instance of the AesGcmStrict class with a provided key.</summary>
		/// <param name="key">The secret key to use for this instance.</param>
		/// <exception cref="ArgumentNullException">The <paramref name="key"/> parameter is <code>null</code>.</exception>
		public AesGcmStrict(ReadOnlySpan<byte> key) => _aesGcm = new AesGcm(key);

		/// <summary>Initializes a new instance of the AesGcmStrict class with a provided key.</summary>
		/// <param name="key">The secret key to use for this instance.</param>
		/// <exception cref="ArgumentNullException">The <paramref name="key"/> parameter is <code>null</code>.</exception>
		public AesGcmStrict(byte[] key) => _aesGcm = new AesGcm(key);

		/// <summary>Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a separate buffer.</summary>
		/// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
		/// <param name="plaintext">The content to encrypt.</param>
		/// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
		/// <param name="tag">The byte array to receive the generated authentication tag.</param>
		/// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
		/// <exception cref="ArgumentException">The <paramref name="plaintext"/> and the <paramref name="ciphertext"/> parameters do not have the same length.</exception>
		/// <exception cref="ArgumentException">The <paramref name="nonce"/> parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
		/// <exception cref="ArgumentException">The <paramref name="tag"/> parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
		/// <exception cref="ArgumentNullException">The <paramref name="nonce"/>, <paramref name="ciphertext"/>, <paramref name="tag"/>, or <paramref name="plaintext"/> parameter is <code>null</code>.</exception>
		/// <exception cref="CryptographicException">The encryption operation failed.</exception>
		/// <remarks>The security guarantees of the AES-GCM algorithm mode require that the same nonce value is never used twice with the same key.</remarks>
		public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[]? associatedData = default)
		{
			CheckParameters(tag);
			_aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		}//Encrypt()

		/// <summary>Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a separate buffer.</summary>
		/// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
		/// <param name="plaintext">The content to encrypt.</param>
		/// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
		/// <param name="tag">The byte array to receive the generated authentication tag.</param>
		/// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
		/// <exception cref="ArgumentException">The <paramref name="plaintext"/> and the <paramref name="ciphertext"/> parameters do not have the same length.</exception>
		/// <exception cref="ArgumentException">The <paramref name="nonce"/> parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
		/// <exception cref="ArgumentException">The <paramref name="tag"/> parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
		/// <exception cref="ArgumentNullException">The <paramref name="nonce"/>, <paramref name="ciphertext"/>, <paramref name="tag"/>, or <paramref name="plaintext"/> parameter is <code>null</code>.</exception>
		/// <exception cref="CryptographicException">The encryption operation failed.</exception>
		/// <remarks>The security guarantees of the AES-GCM algorithm mode require that the same nonce value is never used twice with the same key.</remarks>
		public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
		{
			CheckParameters(tag);
			_aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		}//Encrypt()

		/// <summary>Decrypts the ciphertext into the provided destination buffer if the authentication tag can be validated.</summary>
		/// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
		/// <param name="ciphertext">The encrypted content to decrypt.</param>
		/// <param name="tag">The authentication tag produced for this message during encryption.</param>
		/// <param name="plaintext">The byte array to receive the decrypted contents.</param>
		/// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
		/// <exception cref="ArgumentException">The <paramref name="plaintext"/> and the <paramref name="ciphertext"/> parameters do not have the same length.</exception>
		/// <exception cref="ArgumentException">The <paramref name="nonce"/> parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
		/// <exception cref="ArgumentException">The <paramref name="tag"/> parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
		/// <exception cref="ArgumentNullException">The <paramref name="nonce"/>, <paramref name="ciphertext"/>, <paramref name="tag"/>, or <paramref name="plaintext"/> parameter is <code>null</code>.</exception>
		/// <exception cref="CryptographicException">The tag value could not be verified, or the decryption operation otherwise failed.</exception>
		/// <remarks>If <paramref name="tag"/> cannot be validated (using the key, <paramref name="nonce"/>, <paramref name="ciphertext"/>, and <paramref name="associatedData"/> values), then <paramref name="plaintext"/> is cleared.</remarks>
		public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[]? associatedData = default)
		{
			CheckParameters(tag);
			_aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
		}//Decrypt()

		/// <summary>Decrypts the ciphertext into the provided destination buffer if the authentication tag can be validated.</summary>
		/// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
		/// <param name="ciphertext">The encrypted content to decrypt.</param>
		/// <param name="tag">The authentication tag produced for this message during encryption.</param>
		/// <param name="plaintext">The byte array to receive the decrypted contents.</param>
		/// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
		/// <exception cref="ArgumentException">The <paramref name="plaintext"/> and the <paramref name="ciphertext"/> parameters do not have the same length.</exception>
		/// <exception cref="ArgumentException">The <paramref name="nonce"/> parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
		/// <exception cref="ArgumentException">The <paramref name="tag"/> parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
		/// <exception cref="ArgumentNullException">The <paramref name="nonce"/>, <paramref name="ciphertext"/>, <paramref name="tag"/>, or <paramref name="plaintext"/> parameter is <code>null</code>.</exception>
		/// <exception cref="CryptographicException">The tag value could not be verified, or the decryption operation otherwise failed.</exception>
		/// <remarks>If <paramref name="tag"/> cannot be validated (using the key, <paramref name="nonce"/>, <paramref name="ciphertext"/>, and <paramref name="associatedData"/> values), then <paramref name="plaintext"/> is cleared.</remarks>
		public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
		{
			CheckParameters(tag);
			_aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
		}//Decrypt()

		/// <summary>Releases the resources used by the current instance of the <see cref="AesGcmStrict"/> class.</summary>
		public void Dispose() => _aesGcm.Dispose();

		static void CheckParameters(ReadOnlySpan<byte> tag)
		{
			if (tag.Length != FIXED_TAG_LENGTH)
				throw new ArgumentException("The specified tag is not a valid size for this algorithm (must be " + FIXED_TAG_LENGTH_STRING + " bytes).", nameof(tag));
		}//CheckParameters()
	}//class AesGcmStrict
}//ns
