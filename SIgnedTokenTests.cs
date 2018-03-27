using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Xunit;

namespace SignedTokenSandbox
{
	// Uses ES256 to sign the token, using the NIST P256/secp256 curve https://tools.ietf.org/html/rfc7518#section-3.4
	// OpenSSL calls this prime256v1.
	// https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations#EC_Private_Key_File_Formats
	//    openssl ecparam -out ec_key.pem -name  prime256v1 -genkey
	//    openssl pkcs8 -topk8 -nocrypt -in ec_key.pem -out private.pem
	//    openssl ec -in ec_key.pem -pubout -out public.pem
	//    openssl asn1parse -in ec_key.pem -dump (to see raw bytes)
	// Requires the random number generator to be secure when signing tokens, see https://en.wikipedia.org/wiki/EdDSA
	// Google and Apple both use ES256 for signed JWTs
	// https://developer.apple.com/library/content/documentation/NetworkingInternetWeb/Conceptual/AppleMusicWebServicesReference/SetUpWebServices.html#//apple_ref/doc/uid/TP40017625-CH2-SW1
	// https://cloud.google.com/iot/docs/how-tos/credentials/jwts
	public class SignedTokenTests
	{
		// https://www.scottbrady91.com/C-Sharp/JWT-Signing-using-ECDSA-in-dotnet-Core
		// https://stackoverflow.com/questions/24251336/import-a-public-key-from-somewhere-else-to-cngkey
		[Fact]
		public void SignedTokenRoundTripGeneratedKeys()
		{
			var (privateKey, publicKey) = GenerateKeys();
			var payload = Encoding.UTF8.GetBytes("hello");
			var signatureBytes = Sign(payload, publicKey, privateKey);

			Assert.True(Verify(payload, signatureBytes, publicKey));
		}

		[Fact]
		public void SignedTokenRoundTripExistingKeys()
		{
			var (privateKey, publicKey) = ReadPem("private.pem");

			var payload = Encoding.UTF8.GetBytes("hello");
			var signatureBytes = Sign(payload, publicKey, privateKey);

			Assert.True(Verify(payload, signatureBytes, publicKey));
		}

		[Fact]
		public void KeyPairsMatch()
		{
			var ecKeys = ReadPem("ec_key.pem");
			var publicKey = ReadPem("public.pem").PublicKey;
			var privateKeys = ReadPem("private.pem");
			Assert.Equal(publicKey, privateKeys.PublicKey);
			Assert.Equal(publicKey, ecKeys.PublicKey);
			Assert.Equal(privateKeys.PrivateKey, ecKeys.PrivateKey);
		}

		// https://jwt.io/
		[Fact]
		public void TokenFormatMatches()
		{
			var jwtHandler = new JwtSecurityTokenHandler();
			var (privateKey, publicKey) = ReadPem("private.pem");

			var jwtToken = jwtHandler.CreateJwtSecurityToken(
				issuer: "auth.example.com",
				audience: "all-apis.example.com",
				issuedAt: new DateTime(2018, 1, 1),
				notBefore: new DateTime(2018, 1, 1),
				expires:  new DateTime(2028, 1, 1),
				subject: new ClaimsIdentity(new[] { new Claim("sub", "2986689"), new Claim("is_admin_consumer", "true") }),
				signingCredentials: new SigningCredentials(new ECDsaSecurityKey(LoadPrivateKey(privateKey)), SecurityAlgorithms.EcdsaSha256)
			);

			string signedToken = jwtHandler.WriteToken(jwtToken);
			Assert.StartsWith("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyOTg2Njg5IiwiaXNfYWRtaW5fY29uc3VtZXIiOiJ0cnVlIiwibmJmIjoxNTE0NzkzNjAwLCJleHAiOjE4MzAzMjY0MDAsImlhdCI6MTUxNDc5MzYwMCwiaXNzIjoiYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6ImFsbC1hcGlzLmV4YW1wbGUuY29tIn0.", signedToken);

			jwtHandler.ValidateToken(signedToken, new TokenValidationParameters
			{
				ValidIssuer = "auth.example.com",
				ValidAudience = "all-apis.example.com",
				IssuerSigningKey = new ECDsaSecurityKey(LoadPublicKey(publicKey))
			}, out var parsedSecurityToken);

			var parsedJwtToken = (JwtSecurityToken) parsedSecurityToken;

			Assert.Equal("2986689", parsedJwtToken.Subject);
			Assert.Equal("true", parsedJwtToken.Claims.First(x => x.Type == "is_admin_consumer").Value);
		}

		[Theory]
		[InlineData("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyOTg2Njg5IiwiaXNfYWRtaW5fY29uc3VtZXIiOiJ0cnVlIiwibmJmIjoxNTE0NzkzNjAwLCJleHAiOjE4MzAzMjY0MDAsImlhdCI6MTUxNDc5MzYwMCwiaXNzIjoiYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6ImFsbC1hcGlzLmV4YW1wbGUuY29tIn0.P5k9R4aocz7FinBoVa0WkYH2jn7C9_hG2846GzAfBeaFcNuN65y5EateEZ1g3tpEMzyQ03YW2wvujt0ORzlvdA")]
		public void ParsesPreviouslySignedToken(string token)
		{
			var jwtHandler = new JwtSecurityTokenHandler();
			var publicKey = ReadPem("public.pem").PublicKey;

			jwtHandler.ValidateToken(token, new TokenValidationParameters
			{
				ValidIssuer = "auth.example.com",
				ValidAudience = "all-apis.example.com",
				IssuerSigningKey = new ECDsaSecurityKey(LoadPublicKey(publicKey))
			}, out var parsedToken);

			var jwtToken = (JwtSecurityToken) parsedToken;

			Assert.Equal("2986689", jwtToken.Subject);
		}

		[Theory]
		[InlineData("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30.1xifFDkLeNVl735O28sR7HGbURRvRnnCDy8zvdLYuCWxFOTIryW2Q1gxw-FxCAQx_awERB-eF0CY87pG9rm-GQ", "SecurityTokenNoExpirationException")]
		[InlineData("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyOTg2Njg5IiwiaXNfYWRtaW5fY29uc3VtZXIiOiJ0cnVlIiwibmJmIjoxNTE0NzkzNjAwLCJleHAiOjE1MTQ3OTM2MDAsImlhdCI6MTUxNDc5MzYwMCwiaXNzIjoiYXV0aC5mYWl0aGxpZmUuY29tIiwiYXVkIjoiYWxsLWFwaXMuZmFpdGhsaWZlLmNvbSJ9.H5MVAxhBrLYYYSIE7LIjREj60d-wHGWAL3HLr2yJt4sfFI3oC3VSCaubP7TsHnLr310Ix60-3cppW7ncl5hUJQ", "SecurityTokenExpiredException")]
		[InlineData("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.1HogBH-GQS4ANFf4effJXmQSkJ5nr1bExZ7nlL7VZPoeHVoeJz4QtMFAAQFrNipRBuhYzny1bOG3zPzD-mUXPA", "SecurityTokenInvalidSignatureException")]
		public void RejectsInvalidToken(string token, string exceptionName)
		{
			var jwtHandler = new JwtSecurityTokenHandler();
			var publicKey = ReadPem("public.pem").PublicKey;

			try
			{
				jwtHandler.ValidateToken(token, new TokenValidationParameters
				{
					ValidAudience = "all-apis.example.com",
					ValidIssuer = "auth.example.com",
					IssuerSigningKey = new ECDsaSecurityKey(LoadPublicKey(publicKey)),
				}, out var parsedToken);
			}
			catch (Exception e)
			{
				Assert.Equal(exceptionName, e.GetType().Name);
			}
		}

		[Theory]
		[InlineData("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyOTg2Njg5IiwiaXNfYWRtaW5fY29uc3VtZXIiOiJ0cnVlIiwibmJmIjoxNTE0NzkzNjAwLCJleHAiOjE4MzAzMjY0MDAsImlhdCI6MTUxNDc5MzYwMCwiaXNzIjoiYXV0aC5mYWl0aGxpZmUuY29tIiwiYXVkIjoiYWxsLWFwaXMuZmFpdGhsaWZlLmNvbSJ9.AQujSTqoBaG-VtLWi6G5A-_iPAgfH3du4U1-XNU0m4Y")]
		public void RejectsChangedSignatureAlgorithm(string token)
		{
			// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
			var jwtHandler = new JwtSecurityTokenHandler();
			var publicKey = ReadPem("public.pem").PublicKey;

			jwtHandler.ValidateToken(token, new TokenValidationParameters
			{
				ValidateIssuer = false,
				ValidateAudience = false,
				IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(publicKey),
			}, out var _);

			Assert.Throws<SecurityTokenInvalidSignatureException>(() =>
				jwtHandler.ValidateToken(token, new TokenValidationParameters
				{
					ValidateIssuer = false,
					ValidateAudience = false,
					IssuerSigningKey = new ECDsaSecurityKey(LoadPublicKey(publicKey)),
				}, out var _));
		}

		[Theory]
		[InlineData("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIyOTg2Njg5In0.")]
		public void RejectsNoSignature(string token)
		{
			// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
			var jwtHandler = new JwtSecurityTokenHandler();
			var publicKey = ReadPem("public.pem").PublicKey;

			Assert.Throws<SecurityTokenInvalidSignatureException>(() =>
				jwtHandler.ValidateToken(token, new TokenValidationParameters
				{
					ValidateIssuer = false,
					ValidateAudience = false,
					IssuerSigningKey = new ECDsaSecurityKey(LoadPublicKey(publicKey)),
				}, out var _));
		}

		private (byte[] PrivateKey, byte[] PublicKey) GenerateKeys()
		{
			var generator = new ECKeyPairGenerator();
			var curve = SecNamedCurves.GetByName("secp256r1");

			generator.Init(new ECKeyGenerationParameters(new ECDomainParameters(curve.Curve, curve.G, curve.N), new SecureRandom(new RandomGenerator())));
			var pair = generator.GenerateKeyPair();

			var privateKey = (ECPrivateKeyParameters) pair.Private;
			var publicKey = (ECPublicKeyParameters) pair.Public;

			return (privateKey.D.ToByteArrayUnsigned(), publicKey.Q.GetEncoded());
		}

		private (byte[] PrivateKey, byte[] PublicKey) ReadPem(string pemFile)
		{
			using (var reader = File.OpenText(pemFile))
			{
				var pemReader = new PemReader(reader);
				object o;
				while ((o = pemReader.ReadObject()) != null)
				{
					if (o is AsymmetricCipherKeyPair pair)
					{
						var privateKeyFromPair = ((ECPrivateKeyParameters) pair.Private).D.ToByteArrayUnsigned();
						var publicKeyFromPair = ((ECPublicKeyParameters) pair.Public).Q.GetEncoded();

						return (PrivateKey: privateKeyFromPair, PublicKey: publicKeyFromPair);
					}

					if (o is ECPrivateKeyParameters privateKey)
					{
						var curve = SecNamedCurves.GetByName("secp256r1");
						var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N);

						var publicKeyParameters = new ECPublicKeyParameters(domain.G.Multiply(new BigInteger(1, privateKey.D.ToByteArrayUnsigned())), domain);

						return (PrivateKey: privateKey.D.ToByteArrayUnsigned(), PublicKey: publicKeyParameters.Q.GetEncoded());
					}

					if (o is ECPublicKeyParameters publicKey)
					{
						return (PrivateKey: null, PublicKey: publicKey.Q.GetEncoded());
					}
				}

				throw new InvalidOperationException("Key pair was not found in PEM file");
			}
		}

		private bool Verify(byte[] payload, byte[] signature, byte[] publicKey)
		{
			var key = new ECDsaSecurityKey(LoadPublicKey(publicKey));
			var provider = new AsymmetricSignatureProvider(key, SecurityAlgorithms.EcdsaSha256Signature);
			return provider.Verify(payload, signature);
		}

		private byte[] Sign(byte[] payload, byte[] publicKey, byte[] privateKey)
		{
			var key = new ECDsaSecurityKey(LoadPrivateKey(privateKey));
			var provider = new AsymmetricSignatureProvider(key, SecurityAlgorithms.EcdsaSha256Signature);

			return provider.Sign(payload);
		}

		private static ECDsa LoadPublicKey(byte[] key)
		{
			return ECDsa.Create(new ECParameters
			{
				Curve = ECCurve.NamedCurves.nistP256,
				Q = new ECPoint
				{
					X = key.Skip(1).Take(32).ToArray(),
					Y = key.Skip(33).ToArray(),
				}
			});
		}

		private static ECDsa LoadPrivateKey(byte[] key)
		{
			var privKeyInt = new BigInteger(1, key);
			var parameters = SecNamedCurves.GetByName("secp256r1");
			var ecPoint = parameters.G.Multiply(privKeyInt);
			var privKeyX = ecPoint.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned();
			var privKeyY = ecPoint.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned();

			return ECDsa.Create(new ECParameters
			{
				Curve = ECCurve.NamedCurves.nistP256,
				D = privKeyInt.ToByteArrayUnsigned(),
				Q = new ECPoint
				{
					X = privKeyX,
					Y = privKeyY,
				}
			});
		}

		private class RandomGenerator : IRandomGenerator
		{
			public void NextBytes(byte[] bytes)
			{
				using (var random = RandomNumberGenerator.Create())
					random.GetBytes(bytes);
			}

			public void AddSeedMaterial(byte[] seed) => throw new NotImplementedException();

			public void AddSeedMaterial(long seed) => throw new NotImplementedException();

			public void NextBytes(byte[] bytes, int start, int len) => throw new NotImplementedException();
		}
	}
}
