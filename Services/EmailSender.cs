using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Net.Mail;

namespace IdentityManager.Services
{
	public class EmailSender : IEmailSender
	{
		public string Config {  get; set; }
		public EmailSender(IConfiguration _config)
		{
			Config = _config.GetValue<string>("SendGrid:SecretKey");
		}
		public async Task SendEmailAsync(string email, string subject, string htmlMessage)
		{
			var client = new SendGridClient(Config);
			var from = new EmailAddress("hello@MohamedAbolhassan.com", "Example User");
			var to = new EmailAddress(email);
			var msg = MailHelper.CreateSingleEmail(from, to, subject, " ", htmlMessage);
			var response = await client.SendEmailAsync(msg)/*.ConfigureAwait(false)*/;
		}
	}
}
