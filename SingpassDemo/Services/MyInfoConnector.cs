using SingpassDemo.Models;
using SingpassDemo.Models.MyInfo;
using System.Collections.Specialized;
using Newtonsoft.Json;
using SingpassDemo.Models.Crypto;
using SingpassDemo.Services;
using Jose;

public class MyInfoConnector
{
	private readonly MyInfoConnectorConfig _config;
    private readonly SecurityHelper _securityHelper;
    private readonly MyInfoHttpClient _myInfoHttpClient;

    public MyInfoConnector(MyInfoConnectorConfig config)
    {
		_config = config;
		_securityHelper = new SecurityHelper();
		_myInfoHttpClient = new MyInfoHttpClient();
	}

    public async Task<string> GetMyInfoPersonData(
	    string authCode, 
	    string codeVerifier, 
	    string privateSigningKey, 
	    string privateEncryptionKey)
    {
		var sessionEphemeralKeyPair = _securityHelper.GenerateSessionKeyPair();
		var accessToken = await CallTokenApi(authCode, privateSigningKey, codeVerifier, sessionEphemeralKeyPair);
		var personData = await GetPersonDataWithToken(accessToken.AccessToken, sessionEphemeralKeyPair, privateEncryptionKey);

		return personData;
	}

    public CodeChallengeModel GeneratePkceCodePair()
    {
        var codeVerifier = _securityHelper.GenerateRandomString(32);
		var codeChallenge = _securityHelper.Base64UrlEncode(_securityHelper.Sha256(codeVerifier));

		return new CodeChallengeModel
		{
			CodeVerifier = codeVerifier, CodeChallenge = codeChallenge
		};
    }

    private async Task<AccessTokenResponse> CallTokenApi(
	    string authCode, 
	    string privateSigningKey, 
	    string codeVerifier,
	    EphemeralKeyPair sessionEphemeralKeyPair)
    {
	    var clientAssertion = _securityHelper.GenerateClientAssertion(_config.GetTokenUrl, _config.ClientId, privateSigningKey, sessionEphemeralKeyPair);

        var @params = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", authCode },
            { "redirect_uri", _config.RedirectUrl },
            { "client_id", _config.ClientId },
            { "code_verifier", codeVerifier },
            { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
            { "client_assertion", clientAssertion }
        };

        var dPoP = _securityHelper.GenerateDpop(_config.GetTokenUrl, null, "POST", sessionEphemeralKeyPair);

        var headers = new NameValueCollection
        {
	        {"Cache-Control", "no-cache"},
	        {"DPoP", dPoP}
        };

        var tokenUrl = _config.GetTokenUrl;
        var accessToken = await _myInfoHttpClient.PostRequestAsync<AccessTokenResponse>(tokenUrl, headers, @params);

        return accessToken;
    }

	private async Task<string> GetPersonDataWithToken(
		string accessToken, 
		EphemeralKeyPair sessionEphemeralKeyPair, 
		string privateEncryptionKey)
	{
		var appJwks = GetAppJwks();
		var decodedJws = _securityHelper.DecodeJws(accessToken, appJwks);
		var decodedToken = JsonConvert.DeserializeObject<MyInfoTokenModel>(decodedJws);

		if (decodedToken == null)
	    {
		    throw new Exception("Invalid Token");
	    }

	    var uinfin = decodedToken.sub;

	    if (string.IsNullOrEmpty(uinfin))
	    {
		    throw new Exception("UINFIN not found");
	    }

	    var personResult = await CallPersonApi(uinfin, accessToken, sessionEphemeralKeyPair);

	    if (personResult == null)
	    {
		    throw new Exception("Unknown Error");
	    }

	    var jws = _securityHelper.DecryptJweWithKey(personResult, privateEncryptionKey);
		var myInfoJwks = await GetMyInfoJwks();
		var decodedData = _securityHelper.DecodeJws(jws, myInfoJwks);

	    return decodedData;
    }

	private async Task<dynamic> CallPersonApi(
		string sub, 
		string accessToken,
		EphemeralKeyPair sessionEphemeralKeyPair)
	{
		var urlLink = _config.GetPersonUrl + "/" + sub;
		var strParams = "scope=" + Uri.EscapeDataString(_config.Scope);

		var headers = new NameValueCollection { { "Cache-Control", "no-cache" } };

		var ath = _securityHelper.Base64UrlEncode(_securityHelper.Sha256(accessToken));
		var dpopToken = _securityHelper.GenerateDpop(urlLink, ath, "GET", sessionEphemeralKeyPair);
		headers.Add("dpop", dpopToken);
		headers.Add("Authorization", "DPoP " + accessToken);

		var parsedUrl = new Uri(_config.GetPersonUrl);
		var domain = parsedUrl.Host;
		var requestPath = parsedUrl.AbsolutePath + "/" + sub + "?" + strParams;

		var personData = await _myInfoHttpClient.GetRequestAsync("https://" + domain + requestPath, headers);

		return personData;
	}

	private async Task<JwkSet> GetMyInfoJwks()
	{
		var jwksJson = await _myInfoHttpClient.GetJsonData(_config.MyInfoJwksUrl);
		var keyStore = JwkSet.FromJson(jwksJson, new JsonMapper());
		return keyStore;
	}

	/// <summary>
	/// A copy of MyInfoJwks is used since there is no access to the Singpass portal
	/// to add your own endpoint with Jwks to the whitelist
	/// </summary>
	private JwkSet GetAppJwks()
	{
		var jwks = new Dictionary<string, object>
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
		var keyStore = JwkSet.FromDictionary(jwks);
		return keyStore;
	}
}
