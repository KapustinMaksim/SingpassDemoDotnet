using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SingpassDemo.Models;

namespace SingpassDemo.Controllers
{
	[Route("")]
	[ApiController]
	public class SingpassConnectorController : ControllerBase
	{
		private readonly MyInfoConnector _myInfoConnector;
		private readonly MyInfoConnectorConfig _config;
		private readonly AppConfig _appConfig;

		public static ConcurrentDictionary<string, string> _sessionIdCache = new();

		public SingpassConnectorController()
		{
			_appConfig = new AppConfig();
			_config = new MyInfoConnectorConfig(_appConfig);
			_myInfoConnector = new MyInfoConnector(_config);
		}

		[Route("getEnv")]
		[HttpGet]
		public object GetEnv()
		{
			var configs = new
			{
				clientId = _appConfig.ClientId,
				redirectUrl = _appConfig.AppCallbackUrl,
				scope = _appConfig.Scopes,
				purpose_id = _appConfig.PurposeId,
				authApiUrl = _appConfig.ApiAuthorizeUrl
			};
			return Ok(configs);
		}

		[Route("callback")]
		public IActionResult Callback()
		{
			var code = Request.Query["code"];
			return Redirect($"http://localhost:3001?callback=true&code={code}");
		}

		[Route("generateCodeChallenge")]
		[HttpPost]
		public object GenerateCodeChallenge()
		{
			var pkceCodePair = _myInfoConnector.GeneratePkceCodePair();

			var sessionId = Guid.NewGuid().ToString();
			_sessionIdCache[sessionId] = pkceCodePair.CodeVerifier;
			Response.Cookies.Append("sid", sessionId);

			return Ok(pkceCodePair.CodeChallenge);
		}

		[Route("getPersonData")]
		[HttpGet]
		public async Task<object> GetPersonData(string authCode)
		{
			var sidVal = Request.Cookies["sid"];
			var codeVerifier = _sessionIdCache[sidVal];

			var privateSigningKey = await System.IO.File.ReadAllTextAsync(_appConfig.PrivateSigningKeyPath);
			var privateEncryptionKey = await System.IO.File.ReadAllTextAsync(_appConfig.PrivateEncryptionKeyPath);

			var personDataJson = await _myInfoConnector.GetMyInfoPersonData(
				authCode,
				codeVerifier,
				privateSigningKey,
				privateEncryptionKey
			);

			var jsonDocument = JsonDocument.Parse(personDataJson);

			var formattedJson = JsonSerializer.Serialize(jsonDocument.RootElement, new JsonSerializerOptions
			{
				WriteIndented = true
			});

			return Ok(formattedJson);
		}
	}
}
