using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class RoleController : Controller
    {
        private readonly AppDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(AppDbContext db , UserManager<ApplicationUser> userManager , RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            
            var roles = _db.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string roleId)
        {
            if (string.IsNullOrEmpty(roleId))
            {
                return View();
            }
            else
            {
                var objfromdb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
                return View(objfromdb);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if(await _roleManager.RoleExistsAsync(roleObj.Name))
            {

            }
            if (String.IsNullOrEmpty(roleObj.NormalizedName))
            {
                await _roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
            }
            else
            {
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleObj.Id);
                objFromDb.Name = roleObj.Name;
                objFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(objFromDb);
                //return View(objFromDb);
            }
            return RedirectToAction(nameof(Index));
        }
		[HttpPost]
		[ValidateAntiForgeryToken]
        //[Authorize(Roles =SD.SuperAdmin)]
        [Authorize(Policy = "OnlySuperAdminChecker")]
		public async Task<IActionResult> Delete(string roleId)
        {
            var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
            if (objFromDb != null)
            {
                var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == roleId).Count();
                if(userRolesForThisRole > 0)
                {
                    return RedirectToAction(nameof(Index));
                }

				var result = await _roleManager.DeleteAsync(objFromDb);
			}
            return RedirectToAction(nameof(Index));
		}


	}
}
