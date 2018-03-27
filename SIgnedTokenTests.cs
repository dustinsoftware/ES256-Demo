using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace SignedTokenSandbox
{
	// Uses ES256 to sign the token, using the NIST P256/secp256 curve https://tools.ietf.org/html/rfc7518#section-3.4
	// OpenSSL calls this prime256v1.
	// https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations#EC_Private_Key_File_Formats
	//    openssl ecparam -out ec_key.pem -name  prime256v1 -genkey
	//    openssl pkcs8 -topk8 -nocrypt -in ec_key.pem -out private.pem
	//    https://stackoverflow.com/questions/43160232/how-do-i-load-an-openssl-ecdsa-key-into-c
	//    openssl asn1parse -in ec_key.pem -dump
	// Requires the random number generator to be secure when signing tokens, see https://en.wikipedia.org/wiki/EdDSA
	// https://developer.apple.com/library/content/documentation/NetworkingInternetWeb/Conceptual/AppleMusicWebServicesReference/SetUpWebServices.html#//apple_ref/doc/uid/TP40017625-CH2-SW1
	// https://cloud.google.com/iot/docs/how-tos/credentials/jwts
	public class UnitTest1
	{
		// https://www.scottbrady91.com/C-Sharp/JWT-Signing-using-ECDSA-in-dotnet-Core
		// https://stackoverflow.com/questions/24251336/import-a-public-key-from-somewhere-else-to-cngkey
		[Fact]
		public void SignedTokenRoundTripGeneratedKeys()
		{
			var (privateKey, publicKey) = GenerateKeys();
			var payload = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { testClaim = "hello" }));
			var signatureBytes = Sign(payload, publicKey, privateKey);

			Assert.True(Verify(payload, signatureBytes, publicKey));
		}

		[Fact]
		public void SignedTokenRoundTripExistingKeys()
		{
			var (privateKey, publicKey) = ReadPem("private.pem");

			var payload = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { testClaim = "hello" }));
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
		public void ExistingTokenParses()
		{

		}

		private (byte[], byte[]) GenerateKeys()
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

		private static string CreateSignedJwt(ECDsa ecdsa)
		{
			var jwtHandler = new JwtSecurityTokenHandler();

			var jwtToken = jwtHandler.CreateJwtSecurityToken(
				issuer: "auth.example.com",
				expires: DateTime.UtcNow.AddMinutes(1),
				signingCredentials: new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256)
			);

			return jwtHandler.WriteToken(jwtToken);
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

		private static byte[] FromHexString(string hex)
		{
			var hexAsBytes = new byte[hex.Length / 2];
			for (var i = 0; i < hex.Length; i += 2)
				hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

			return hexAsBytes;
		}

		private class RandomGenerator : IRandomGenerator
		{
			public void AddSeedMaterial(byte[] seed)
			{
				throw new NotImplementedException();
			}

			public void AddSeedMaterial(long seed)
			{
				throw new NotImplementedException();
			}

			public void NextBytes(byte[] bytes)
			{
				using (var random = RandomNumberGenerator.Create())
				{
					random.GetBytes(bytes);
				}
			}

			public void NextBytes(byte[] bytes, int start, int len)
			{
				throw new NotImplementedException();
			}
		}

		private static string _publicKey = "04e33993f0210a4973a94c26667007d1b56fe886e8b3c2afdd66aa9e4937478ad20acfbdc666e3cec3510ce85d40365fc2045e5adb7e675198cf57c6638efa1bdb";
		private static string _privateKey = "c711e5080f2b58260fe19741a7913e8301c1128ec8e80b8009406e5047e6e1ef";
	}
}
