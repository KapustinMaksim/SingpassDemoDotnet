using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Text;
using Jose;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using SingpassDemo.Enums;
using SingpassDemo.Models.Crypto;
using PemReader = Org.BouncyCastle.OpenSsl.PemReader;
using PemWriter = Org.BouncyCastle.OpenSsl.PemWriter;
using StringBuilder = System.Text.StringBuilder;

namespace SingpassDemo.Services;

public class SecurityHelper
{
	public string GenerateRandomString(int length)
	{
		var randomString = new StringBuilder();
		var random = new Random();
		const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

		for (int i = 0; i < length; i++)
		{
			randomString.Append(chars[random.Next(chars.Length)]);
		}

		return randomString.ToString();
	}

	public string DecodeJws(string compactJws, JwkKeyType keyType)
	{
		var jwks = GetJwks();

		var keyStore = JwkSet.FromDictionary(jwks);
		var key = keyStore.Keys.First(k => k.Use == keyType.ToString());

		var result = JWT.Decode(compactJws, key);

		return result;
	}

	public string DecryptJweWithKey(string compactJwe, string decryptionPrivateKey)
	{
		var privateKeyParams = (ECPrivateKeyParameters)JwkPemToAsymmetricKey(decryptionPrivateKey);
		using ECDsa ecdsa = ECDsa.Create(new ECParameters
		{
			Curve = ECCurve.NamedCurves.nistP256,
			D = privateKeyParams.D.ToByteArrayUnsigned(),
		});

		var decryptedData = JWT.Decode(compactJwe, new Jwk(ecdsa));

		return decryptedData;
	}

	/// <summary>
	/// Generate Key Pair
	///	This method will generate a keypair which consists of an eliptic curve public key and a private key in PEM format.
	/// </summary>
	/// <returns>Returns an object which consists of a public key and a private key</returns>
	public EphemeralKeyPair GenerateSessionKeyPair()
	{
		// Create key generation parameters
		var genParam = new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom());

		// Initialize the key pair generator with the specified parameters
		var generator = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
		generator.Init(genParam);

		// Generate the key pair
		var keyPair = generator.GenerateKeyPair();

		// Convert the keys to PEM format
		var publicKey = ToPemString(keyPair.Public);
		var privateKey = ToPemString(keyPair.Private);

		return new EphemeralKeyPair
		{
			PrivateKey = privateKey,
			PublicKey = publicKey
		};
	}

	public string GenerateClientAssertion(string url, string clientId, string privateSigningKey, string jktThumbprint)
	{
		try
		{
			var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

			var payload = new
			{
				sub = clientId,
				jti = GenerateRandomString(40),
				aud = url,
				iss = clientId,
				iat = now,
				exp = now + 300,
				cnf = new
				{
					jkt = jktThumbprint
				}
			};

			var payloadJson = JsonConvert.SerializeObject(payload);

			var privateKeyParams = (ECPrivateKeyParameters)JwkPemToAsymmetricKey(privateSigningKey);
			using ECDsa ecdsa = ECDsa.Create(new ECParameters
			{
				Curve = ECCurve.NamedCurves.nistP256,
				D = privateKeyParams.D.ToByteArrayUnsigned(),
			});

			var jwtToken = JWT.Encode(payloadJson, ecdsa, JwsAlgorithm.ES256, extraHeaders: new Dictionary<string, object>
			{
				{ "kid", "aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ" }, //todo
				{ "typ", "JWT" }
			});

			return jwtToken;
		}
		catch (Exception)
		{
			throw new Exception("Error generating client assertion");
		}
	}

	public string GenerateDpop(string url, string ath, string method, EphemeralKeyPair sessionEphemeralKeyPair)
	{
		var now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
		var payload = new
		{
			htu = url,
			htm = method,
			jti = GenerateRandomString(40),
			iat = now,
			exp = now + 120,
			ath = ath //append ath if passed in (Required for /person call)
		};
		
		var payloadJson = JsonConvert.SerializeObject(payload);

		var publicKeyParams = (ECPublicKeyParameters)JwkPemToAsymmetricKey(sessionEphemeralKeyPair.PublicKey);
		
		var jwk = new
		{
			kty = "EC", 
			crv = "P-256",
			use = "sig",
			alg = "ES256",
			x = Base64UrlEncode(publicKeyParams.Q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned()), 
			y = Base64UrlEncode(publicKeyParams.Q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned())
		};

		var privateKeyParams = (ECPrivateKeyParameters)JwkPemToAsymmetricKey(sessionEphemeralKeyPair.PrivateKey);
		using ECDsa ecdsa = ECDsa.Create(new ECParameters
		{
			Curve = ECCurve.NamedCurves.nistP256,
			D = privateKeyParams.D.ToByteArrayUnsigned(),
		});

		var jwtToken = JWT.Encode(payloadJson, ecdsa, JwsAlgorithm.ES256, extraHeaders: new Dictionary<string, object>
		{
			{ "jwk", jwk },
			{ "typ", "dpop+jwt" }
		});

		Console.WriteLine("Encoded DPoP: " + jwtToken);
		return jwtToken;
	}

	public string Base64UrlEncode(byte[] bytes)
	{
		return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').Replace("=", "");
	}

	public byte[] Sha256(string buffer)
	{
		using var sha256 = SHA256.Create();
		return sha256.ComputeHash(Encoding.UTF8.GetBytes(buffer));
	}

	public string GenerateJwkThumbprint(string jwkPem)
	{
		var pubKey = new Chilkat.PublicKey();
		pubKey.LoadFromString(jwkPem);
		var thumbprint = pubKey.GetJwkThumbprint("SHA256");
		return thumbprint;
	}

	private string ToPemString(AsymmetricKeyParameter key)
	{
		var stringWriter = new StringWriter();
		var pemWriter = new PemWriter(stringWriter);
		pemWriter.WriteObject(key);
		pemWriter.Writer.Flush();
		return stringWriter.ToString();
	}

	private AsymmetricKeyParameter JwkPemToAsymmetricKey(string jwkPem)
	{
		using StringReader reader = new StringReader(jwkPem);
		var pemReader = new PemReader(reader);
		var keyObject = pemReader.ReadObject();

		if (keyObject is ECPublicKeyParameters ecPublicKey)
		{
			return ecPublicKey;
		}

		if (keyObject is AsymmetricCipherKeyPair cipherKeyPair)
		{
			return cipherKeyPair.Private;
		}

		throw new InvalidOperationException("Invalid JWK PEM format or unsupported key type.");
	}

	private static IDictionary<string, object> GetJwks()
	{
		//todo this keys hardcoded for demo purposes
		var result = new Dictionary<string, object>
		{
			{"keys", new []
				{
					new Dictionary<string, object>{
						{"alg",  "ES256"},
						{"use", "sig"},
						{"kty", "EC"},
						{"kid", "AFMnnKRWTaBYEhNfEB6iQ5ErC1yqGVyZchH8A7nl_yM"},
						{"crv", "P-256"},
						{"x", "L_GG9F-hIWXxUEWCB4Fco6zXJkbaU_aUMSbHVbwEwso"},
						{"y", "lNPEj7SHn5IFsO76Xel13d3NDlql8JyToZFylm5V-kU"}
					},
					new Dictionary<string, object> {
						{"alg",  "ECDH-ES+A256KW"},
						{"use", "enc"},
						{"kty", "EC"},
						{"kid", "M-JXqh0gh1GGUUdzNue3IUDyUiagqjHathnscUk2nS8"},
						{"crv", "P-256"},
						{"x", "qrR8PAUO6fDouV-6mVdix5IyrVMtu0PVS0nOqWBZosA"},
						{"y", "6xSbySYW6ke2V727TCgSOPiH4XSDgxFCUrAAMSbl9tI"}
					}
				}
			}
		};

		return result;
	}
}