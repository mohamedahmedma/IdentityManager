﻿using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models.ViewModels
{
	public class ForgotPasswordVM
	{
		[Required]
		[EmailAddress]
		public string Email { get; set; }
	}
}
