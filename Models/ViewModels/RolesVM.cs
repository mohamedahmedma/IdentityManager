namespace IdentityManager.Models.ViewModels
{
	public class RolesVM
	{
		public RolesVM()
		{
			RoleList = [];
		}
		public ApplicationUser User { get; set; }
		public List<RoleSelection> RoleList { get; set; }

	}

	public class RoleSelection
	{
		public string RoleName { get; set; }
		public bool IsSelected { get; set; }
	}
}
