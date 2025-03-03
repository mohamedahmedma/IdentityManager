using Microsoft.AspNetCore.Identity.UI.Services;
using System;
using MailChimp.Net;
using MailChimp.Net.Core;
using MailChimp.Net.Models;
using MailChimp.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace IdentityManager.Services
{
	public class Mailchimp : IEmailSender
	{
		public string Config {  get; set; }
		public Mailchimp(IConfiguration _config)
		{
			Config = _config.GetValue<string>("SendGrid:SecretKey");
		}

		public Task SendEmailAsync(string email, string subject, string htmlMessage)
		{
			return Task.CompletedTask;
		}
	}
}
