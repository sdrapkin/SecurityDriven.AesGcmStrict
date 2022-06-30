# **AesGcmStrict (.NET)** [![NuGet](https://img.shields.io/nuget/v/AesGcmStrict.svg)](https://www.nuget.org/packages/AesGcmStrict/)

### by [Stan Drapkin](https://github.com/sdrapkin/)

## `AesGcmStrict` class:
* Wraps [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm) and enforces [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm) Tag to be exactly `16` bytes. Use `AesGcmStrict` instead of [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm).
* [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm) allows truncated Tags: any [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm)-provided Tag truncated to ex. 12 bytes will successfully decrypt.

## Example of the problem:
```csharp
Span<byte> plaintext = Encoding.UTF8.GetBytes("Hello World!");
Span<byte> key = new byte[32];
Span<byte> nonce = new byte[12];
Span<byte> ciphertext = new byte[plaintext.Length];
Span<byte> tag = new byte[16]; // generating a 16-byte Tag!

using var gcm = new AesGcm(key);

Console.WriteLine(Encoding.UTF8.GetString(plaintext));

gcm.Encrypt(nonce, plaintext, ciphertext, tag);
plaintext.Clear();
tag = tag.Slice(0, 12); // truncating the Tag to ex. 12 bytes
gcm.Decrypt(nonce, ciphertext, tag, plaintext); // decrypts successfully (PROBLEM)
Console.WriteLine(Encoding.UTF8.GetString(plaintext));
```

Most users of [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm) might expect ~128 bits of Tag-security, but effectively get only ~96 bits at best.

## How to fix with `AesGcmStrict`:
1. Add the namespace: `using SecurityDriven;`
2. Replace `AesGcm` with `AesGcmStrict`

## Same example with `AesGcmStrict`:
```csharp
// using SecurityDriven;
Span<byte> plaintext = Encoding.UTF8.GetBytes("Hello World!");
Span<byte> key = new byte[32];
Span<byte> nonce = new byte[12];
Span<byte> ciphertext = new byte[plaintext.Length];
Span<byte> tag = new byte[16]; // generating a 16-byte Tag!

using var gcm = new AesGcm(key);

Console.WriteLine(Encoding.UTF8.GetString(plaintext));

gcm.Encrypt(nonce, plaintext, ciphertext, tag);
plaintext.Clear();
tag = tag.Slice(0, 12); // truncating the Tag to ex. 12 bytes
gcm.Decrypt(nonce, ciphertext, tag, plaintext); // throws ArgumentException (tag must be 16 bytes)
Console.WriteLine(Encoding.UTF8.GetString(plaintext));
```
