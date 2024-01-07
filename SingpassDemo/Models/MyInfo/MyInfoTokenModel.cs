namespace SingpassDemo.Models.MyInfo
{
	public class MyInfoTokenModel
	{
		public string sub { get; set; }
		public string jti { get; set; }
		public string scope { get; set; }
		public int expires_in { get; set; }
		public string aud { get; set; }
		public string realm { get; set; }
		public string iss { get; set; }
		public MyInfoClientModel client { get; set; }
		public MyInfoCnfModel cnf { get; set; }
		public string jku { get; set; }
		public int iat { get; set; }
		public int nbf { get; set; }
		public int exp { get; set; }
	}

	public class MyInfoClientModel
	{
		public string client_id { get; set; }
		public string client_name { get; set; }
		public string entity_uen { get; set; }
		public string entity_name { get; set; }
	}

	public class MyInfoCnfModel
	{
		public string jkt { get; set; }
	}

}
