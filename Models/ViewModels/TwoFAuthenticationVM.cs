﻿namespace IdentityManager.Models.ViewModels
{
	public class TwoFAuthenticationVM
	{
		public string Code { get; set; }
		public string? Token { get; set; } 
		public string? QRCodeUrl {  get; set; }

	}
}
