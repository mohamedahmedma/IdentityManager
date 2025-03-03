using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly AppDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(AppDbContext db , UserManager<ApplicationUser> userManager
            , RoleManager<IdentityRole> role)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = role;
        }
        public async Task<IActionResult> Index()
        {
            var userlist = _db.ApplicationUsers.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();

            foreach (var user in userlist)
            {
                var role = await _userManager.GetRolesAsync(user) as List<string>;
                user.Role = String.Join("," , role);
                var claim = _userManager.GetClaimsAsync(user).GetAwaiter().GetResult().Select(u => u.Type);
                user.UserClaim = String.Join("," , claim);
            }
            return View(userlist);
        }

        public async Task<IActionResult> ManageRole(string userId)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId);
            if(user == null)
            {
                return NotFound();
            }
            List<string> exsitingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;
            var model = new RolesVM()
            {
                User = user,
            };

            foreach (var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new RoleSelection()
                {
                    RoleName = role.Name,
                };
                if(exsitingUserRoles.Any(c => c == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RoleList.Add(roleSelection);
            }
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesVM roles)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(roles.User.Id);
            if(user == null)
            {
                return NotFound();
            }
            var oldUserRoles = await _userManager.GetRolesAsync(user) ;
            var result = await _userManager.RemoveFromRolesAsync(user, oldUserRoles);

            if(!result.Succeeded)
            {
                return View(roles);
            }
            result = await _userManager.AddToRolesAsync(user, roles.RoleList.Where(x => x.IsSelected).Select(y => y.RoleName));

            
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            ApplicationUser user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
           if(user.LockoutEnd !=null && user.LockoutEnd > DateTime.Now)
            {
                user.LockoutEnd = DateTime.Now;
            }
            else
            {
                user.LockoutEnd = DateTime.Now.AddMinutes(3);
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string userId)
        {
			ApplicationUser user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if(user == null)
            {
                return NotFound();
            }
            _db.ApplicationUsers.Remove(user);
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));
		}



		public async Task<IActionResult> ManageUserClaim(string userId)
		{
			ApplicationUser user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				return NotFound();
			}
			var exsitingUserClaims = await _userManager.GetClaimsAsync(user);
			var model = new ClaimVM()
			{
				User = user,
			};

			foreach (var claim in ClaimStore.claimsList)
			{
				ClaimSelection ClaimSelection = new ClaimSelection()
				{
					ClaimType = claim.Type
				};
				if (exsitingUserClaims.Any(c => c.Type == claim.Type))
				{
					ClaimSelection.IsSelected = true;
				}
				model.ClaimList.Add(ClaimSelection);
			}
			return View(model);
		}
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ManageUserClaim(ClaimVM claimVM)
		{
			ApplicationUser user = await _userManager.FindByIdAsync(claimVM.User.Id);
			if (user == null)
			{
				return NotFound();
			}
			var oldClaim = await _userManager.GetClaimsAsync(user);
			var result = await _userManager.RemoveClaimsAsync(user, oldClaim);

			if (!result.Succeeded)
			{
				return View(claimVM);
			}
			result = await _userManager.AddClaimsAsync(user, claimVM.ClaimList.Where(x => x.IsSelected).Select(y => new Claim(y.ClaimType , y.IsSelected.ToString())));

			if (!result.Succeeded)
			{
				return View(claimVM);
			}


			return RedirectToAction(nameof(Index));
		}
	}
}
