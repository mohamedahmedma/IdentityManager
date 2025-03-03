using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
	[Authorize]
	public class AccessCheckerController : Controller
	{
		//Anyone can access this
		[AllowAnonymous]
		public IActionResult AllAccess() 
		{
			return View();
		}

		//Anyone that has logged in can access
		public IActionResult AuthorizedAccess() 
		{
			return View();
		}

		//account with role of user can access
		[Authorize(Roles =$"{SD.Admin},{SD.User}")]
		public IActionResult UserORAdminRoleAccess() 
		{
			return View();
		}
		[Authorize(Policy ="AdminAndUser")]
		public IActionResult UserANDAdminRoleAccess() 
		{
			return View();
		}

		//account with role of admin can access
		[Authorize(Policy = "Admin")]
		public IActionResult AdminRoleAccess()
		{
			return View();
		}
		//account with role of admin and create claim can access
		[Authorize(Policy = "AdminRole_CreateClaim")]
		public IActionResult Admin_CreateAccess()
		{
			return View();
		}
		//account with role of admin and (create & Edit& Delete) Claims can access (AND not OR)
		[Authorize(Policy = "AdminRole_CreateEditDeleteClaim")]
		public IActionResult Admin_Create_Edit_DeleteAccess()
		{
			return View();
		}
		//account with role of admin and (create & Edit& Delete) Claims can access (AND not OR)
		[Authorize(Policy = "AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole")]
		public IActionResult AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole()
		{
			return View();
		}
		[Authorize(Policy = "AdminWithMoreThan1000Days")]
		public IActionResult OnlyBhrugen()
		{
			return View();
		}

		[Authorize(Policy ="FirstNameAuth")]
        public IActionResult FirstNameAuth()
        {
            return View();
        }
    }
}
