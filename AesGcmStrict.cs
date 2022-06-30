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
		AesGcm _aesGcm;

		const int FIXED_TAG_LENGTH = 16;
		const string FIXED_TAG_LENGTH_STRING = "16";

#if NET6_0_OR_GREATER
		public static bool IsSupported => AesGcm.IsSupported;
#endif
		public static KeySizes NonceByteSizes { get; } = AesGcm.NonceByteSizes;
		public static KeySizes TagByteSizes { get; } = new KeySizes(FIXED_TAG_LENGTH, FIXED_TAG_LENGTH, 1);

		public AesGcmStrict(ReadOnlySpan<byte> key) => _aesGcm = new AesGcm(key);
		public AesGcmStrict(byte[] key) => _aesGcm = new AesGcm(key);

		public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[]? associatedData = null)
		{
			CheckParameters(tag);
			_aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		}//Encrypt()

		public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
		{
			CheckParameters(tag);
			_aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		}//Encrypt()

		public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[]? associatedData = null)
		{
			CheckParameters(tag);
			_aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
		}//Decrypt()

		public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
		{
			CheckParameters(tag);
			_aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
		}//Decrypt()

		static void CheckParameters(ReadOnlySpan<byte> tag)
		{
			if (tag.Length != FIXED_TAG_LENGTH)
				throw new ArgumentException("The specified tag is not a valid size for this algorithm (must be " + FIXED_TAG_LENGTH_STRING + " bytes).", nameof(tag));
		}//CheckParameters()

		public void Dispose() => _aesGcm.Dispose();
	}//class AesGcmStrict
}//ns
