namespace SingpassDemo.Models;

public class MyInfoConnectorConfig
{
    public MyInfoConnectorConfig(AppConfig appConfig)
    {
        ClientId = appConfig.ClientId;
        RedirectUrl = appConfig.AppCallbackUrl;
        Scope = appConfig.Scopes;
        MyInfoJwksUrl = "https://test.authorise.singpass.gov.sg/.well-known/keys.json";
        GetTokenUrl = "https://test.api.myinfo.gov.sg/com/v4/token";
        GetPersonUrl = "https://test.api.myinfo.gov.sg/com/v4/person";
    }

    public string ClientId { get; set; }
    public string RedirectUrl { get; set; }
    public string Scope { get; set; }
    public string MyInfoJwksUrl { get; set; }
    public string GetTokenUrl { get; set; }
    public string GetPersonUrl { get; set; }
}