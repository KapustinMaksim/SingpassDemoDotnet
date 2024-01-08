using System.Collections.Specialized;
using System.Text;
using Newtonsoft.Json;

public class MyInfoHttpClient
{
    private static readonly HttpClient client = new();

    public async Task<string> GetJsonData(string apiUrl)
    {
	    using var httpClient = new HttpClient();
	    var response = await httpClient.GetAsync(apiUrl);
	    var jsonResponse = await response.Content.ReadAsStringAsync();

	    if (!response.IsSuccessStatusCode)
	    {
		    throw new Exception(jsonResponse);
	    }
	    return jsonResponse;
    }

	public async Task<TRes> PostRequestAsync<TRes>(string url, NameValueCollection headers, Dictionary<string, string> body)
    {
		var bodyStringify = ToQueryString(body);

		var request = CreateHttpRequest(url, "POST", headers);
		request.Content = new StringContent(bodyStringify, Encoding.UTF8, "application/x-www-form-urlencoded");
		
		var response = await client.SendAsync(request);

		var jsonResponse = await response.Content.ReadAsStringAsync();

		if (response.IsSuccessStatusCode)
		{
			var result = JsonConvert.DeserializeObject<TRes>(jsonResponse);
			return result;
		}

		throw new HttpRequestException($"Request failed with status code {response.StatusCode}. {jsonResponse}");
	}

    public async Task<string> GetRequestAsync(string url, NameValueCollection headers)
    {
	    var request = CreateHttpRequest(url, "GET", headers);

	    var response = await client.SendAsync(request);

	    var contentResponse = await response.Content.ReadAsStringAsync();

	    if (response.IsSuccessStatusCode)
	    {
		    return contentResponse;
	    }

	    throw new HttpRequestException($"Request failed with status code {response.StatusCode}. {contentResponse}");
    }

    private HttpRequestMessage CreateHttpRequest(string url, string method, NameValueCollection headers)
    {
	    var request = new HttpRequestMessage
	    {
		    Method = new HttpMethod(method),
		    RequestUri = new Uri(url),
		    Headers = {{"User-Agent", "MyInfoNodeJSConnector"}}
	    };

	    foreach (var key in headers.AllKeys)
	    {
		    request.Headers.Add(key, headers[key]);
	    }

	    return request;
    }

    private string ToQueryString(Dictionary<string, string> parameters)
    {
        var keyValuePairs = new List<string>();
        foreach (var parameter in parameters)
        {
            keyValuePairs.Add($"{parameter.Key}={parameter.Value}");
        }

        return string.Join("&", keyValuePairs);
    }
}
