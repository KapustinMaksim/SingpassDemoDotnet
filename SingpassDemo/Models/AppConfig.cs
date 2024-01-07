namespace SingpassDemo.Models;

public class AppConfig
{
	public string ClientId { get; set; } = "STG2-MYINFO-SELF-TEST";
	
	public string SubentityId { get; set; }

	public string PrivateSigningKeyPath { get; set; } =
		"cert/app-signing-private-key.pem";

	public string PrivateEncryptionKeyPath { get; set; } =
		"cert/encryption-private-keys/app-encryption-private-key.pem";
	
	public string AppCallbackUrl { get; set; } = "http://localhost:3001/callback";
	
	public string PurposeId { get; set; } = "demonstration";

	public string Scopes { get; set; } = "uinfin name sex race nationality dob email mobileno regadd housingtype hdbtype marital edulevel noa-basic ownerprivate cpfcontributions cpfbalances";

	public string ApiAuthorizeUrl { get; set; } = "https://test.api.myinfo.gov.sg/com/v4/authorize";
}