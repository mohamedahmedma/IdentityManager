namespace IdentityManager.Models.ViewModels
{
	public class ClaimVM
	{
		public ApplicationUser User { get; set; }
		public List<ClaimSelection> ClaimList {  get; set; }
		public ClaimVM()
		{
			ClaimList = [];
		}
	}

	public class ClaimSelection
	{
		public string ClaimType { get; set; }
		public bool IsSelected { get; set; }
	}
}
