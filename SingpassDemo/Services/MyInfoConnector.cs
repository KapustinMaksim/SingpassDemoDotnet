using SingpassDemo.Models;
using SingpassDemo.Models.MyInfo;
using System.Collections.Specialized;
using SingpassDemo.Enums;
using SingpassDemo.Models.Crypto;
using SingpassDemo.Services;

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

    public async Task<dynamic> GetMyInfoPersonData(
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
	    var jktThumbprint = _securityHelper.GenerateJwkThumbprint(sessionEphemeralKeyPair.PublicKey);
	    var clientAssertion = _securityHelper.GenerateClientAssertion(_config.GetTokenUrl, _config.ClientId, privateSigningKey, jktThumbprint);

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

	private async Task<dynamic> GetPersonDataWithToken(
		string accessToken, 
		EphemeralKeyPair sessionEphemeralKeyPair, 
		string privateEncryptionKey)
    {
	    var decodedToken = _securityHelper.DecodeJws<MyInfoTokenModel>(accessToken, JwkKeyType.sig);

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
	    var decodedData = _securityHelper.DecodeJws<object>(jws, JwkKeyType.enc);

	    return decodedData;
    }

	private async Task<dynamic> CallPersonApi(
		string sub, 
		string accessToken,
		EphemeralKeyPair sessionEphemeralKeyPair)
	{
		var urlLink = _config.GetPersonUrl + "/" + sub;
		var strParams = "scope=" + Uri.EscapeDataString(_config.Scope);

		if (!string.IsNullOrEmpty(_config.SubentityId))
		{
			strParams = $"{strParams}&subentity={_config.SubentityId}";
		}

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

}
