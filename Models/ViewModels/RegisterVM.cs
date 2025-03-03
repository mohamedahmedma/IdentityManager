﻿using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models.ViewModels
{
    public class RegisterVM
    {
        [Required]
        public string Name {  get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [StringLength(100,ErrorMessage ="The {0} must be at least {2} characters long",MinimumLength = 3)]
        public string Password { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password" , ErrorMessage ="The Password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        public IEnumerable<SelectListItem>? RoleList {  get; set; }
        [Display(Name="Role")]
        public string RoleSelected {  get; set; }
    }
}
