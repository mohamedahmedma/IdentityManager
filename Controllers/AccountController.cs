using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;

        public AccountController(UserManager<ApplicationUser> userManager , SignInManager<ApplicationUser> signInManager
            ,IEmailSender emailSender , UrlEncoder urlEncoder , RoleManager<IdentityRole> identityRole)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
            _roleManager = identityRole;
        }
        public async Task<ActionResult> Register(string returnurl = null)
        {
            if (!_roleManager.RoleExistsAsync(SD.Admin).GetAwaiter().GetResult())
            {
                await _roleManager.CreateAsync(new IdentityRole(SD.Admin));
                await _roleManager.CreateAsync(new IdentityRole(SD.User));
            }


            ViewData["ReturnUrl"] = returnurl;
            RegisterVM registerVM = new()
            {
                RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
                {
                    Text = i,
                    Value = i
                })
            };
            return View(registerVM);
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterVM registerVM , string returnurl = null)
        {
			ViewData["ReturnUrl"] = returnurl;
			returnurl = returnurl ?? Url.Content("~/");
			if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerVM.Email,
                    Email = registerVM.Email,
                    Name = registerVM.Name,
                    DateCreated = DateTime.Now,
                };
                var result = await _userManager.CreateAsync(user , registerVM.Password);
                if (result.Succeeded)
                {
                    if(registerVM.RoleSelected != null)
                    {
                        await _userManager.AddToRoleAsync(user, registerVM.RoleSelected);
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, SD.User);
                    }
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackurl = Url.Action("ConfirmationEmail", "Account", new
                    {
                        userid = user.Id,
                        code
                    }, protocol: HttpContext.Request.Scheme);
                    await _signInManager.SignInAsync(user , isPersistent: false);
                    return LocalRedirect(returnurl);
                }
                AddErrors(result);
            }
            registerVM.RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
                {
                    Text = i,
                    Value = i
                });
            return View(registerVM);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
        [AllowAnonymous]
        public IActionResult Login(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }

		[HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
		public async Task<IActionResult> Login(LoginVM registerVM , string returnurl = null)
		{
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
			if (ModelState.IsValid)
			{
				var result = await _signInManager.PasswordSignInAsync(registerVM.Email, registerVM.Password 
                    , registerVM.RememberMe , lockoutOnFailure:true );
                if (result.Succeeded)
                {
                    var user = await _userManager.GetUserAsync(User);
                    var claim = await _userManager.GetClaimsAsync(user);
                    if (claim.Count > 0 )
                    {
                        var x = claim.Where(u => u.Type == "FirstName");
                        if(x == null)
                        {
                            await _userManager.RemoveClaimAsync(user, claim.FirstOrDefault(u => u.Type == "FirstName"));
                        }
                    }
                    await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("FirstName", user.Name));
                    return LocalRedirect(returnurl);
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerfiyAuthenticatorCode), new { returnurl , registerVM.RememberMe });
                }
				
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
					return View(registerVM);
				}
			}
			return View(registerVM);
		}

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerfiyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new VerfiyAuthenticatorVM { ReturnUrl = returnUrl, RememberMe = rememberMe });
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerfiyAuthenticatorCode(VerfiyAuthenticatorVM model)
        {
            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");

			var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe
				,rememberClient:false);
			if (result.IsLockedOut)
			{
				return View("Lockout");
			}
			if (result.Succeeded)
			{
				return LocalRedirect(model.ReturnUrl);
			}
			else
			{
				ModelState.AddModelError(string.Empty, "Invalid login attempt.");
				return View(model);
			}
		}

        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail( string code , string userId)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByIdAsync(userId);
				if (user == null)
				{
					return View("Error");
				}

				var result = await _userManager.ConfirmEmailAsync(user,code);
				if (result.Succeeded)
				{
					return View();
				}
			}
			return View("Error");
		}
		[HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }
        
        [HttpGet]
        [AllowAnonymous]
        public IActionResult NoAccess()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Error()
        {
            return View();
        }  

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordVM model)
        {
            if (ModelState.IsValid)
            {
                var user = await  _userManager.FindByEmailAsync(model.Email);
                if(user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", new {userid = user.Id , code = code}
                , protocol: HttpContext.Request.Scheme);

               await _emailSender.SendEmailAsync(model.Email , "Reset Password - Identity Manager" 
                    , $"Please reset your password by clicking here : <a href='{callbackurl}'>click here</a>");

                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }
            return View(model);
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordVM model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if(user == null)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }

                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }
                AddErrors(result);
            }
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            string AuthUri = string.Format(AuthenticatorUriFormat, _urlEncoder.Encode("IdentityManager") , 
                _urlEncoder.Encode(user.Email) , token);
			var model = new TwoFAuthenticationVM() { Token = token , QRCodeUrl = AuthUri };
			return View(model);
        }
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(TwoFAuthenticationVM model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                bool succeeded = await _userManager
                    .VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider , model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                    return RedirectToAction(nameof(AuthenticatorConfirmation));
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your two factor auth code could not be validated.");
                    return View(model);
                }
                return RedirectToAction(nameof(AuthenticatorConfirmation));
            }
            return View("Error");
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider , string returnUrl = null)
        {
            var redirectUrl = Url.Action("ExternallLoginCallback", "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternallLoginCallback(string returnUrl = null , string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if(remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View(nameof(Login));
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if(info == null) 
            {
                return RedirectToAction(nameof(Login));
            }

            //sign in the user with this external login provider. only if they have a login
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey
                , isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnUrl);
            }
			if (result.RequiresTwoFactor)
			{
				return RedirectToAction(nameof(VerfiyAuthenticatorCode), new { returnUrl });
			}
            else
            {
                //that means user account is not create and we will display a view to create an account
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationVM
                {
                    Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                    Name = info.Principal.FindFirstValue(ClaimTypes.Name)
                });
            }
		}


		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationVM model ,  
            string returnUrl = null)
		{
			returnUrl = returnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
				var info = await _signInManager.GetExternalLoginInfoAsync();
				if (info == null)
				{
					return View("Error");
				}

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Name = model.Email,
                    NormalizedEmail = model.Email.ToUpper(),
                    DateCreated = DateTime.Now
                };
				var result = await _userManager.CreateAsync(user);
				if (result.Succeeded)
				{
					
					await _userManager.AddToRoleAsync(user, SD.User);
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(info); 
                        return LocalRedirect(returnUrl);
					}
				}
				AddErrors(result);
			}
            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
		}

		private void AddErrors(IdentityResult result)
        {
            foreach (var item in result.Errors)
            {
                ModelState.AddModelError(string.Empty, item.Description);
            }
        }
    }
}
