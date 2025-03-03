
using MailChimp.Net;
using MailChimp.Net.Core;
using MailChimp.Net.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
class MailchimpRepo
{
	public static string ApiKey { get; set; }
	private const string ListId = "(your list id)";
	private const int TemplateId = 9999; // (your template id)
	public MailchimpRepo(IConfiguration _config)
	{
		ApiKey = _config.GetValue<string>("SendGrid:SecretKey");
	}
	private MailChimpManager _mailChimpManager = new MailChimpManager(ApiKey);

	private Setting _campaignSettings = new Setting
	{
		ReplyTo = "your@email.com",
		FromName = "The name that others will see when they receive the email",
		Title = "Your campaign title",
		SubjectLine = "The email subject",
	};

	// `html` contains the content of your email using html notation
	public void CreateAndSendCampaign(string html)
	{
		var campaign = _mailChimpManager.Campaigns.AddAsync(new Campaign
		{
			Settings = _campaignSettings,
			Recipients = new Recipient { ListId = ListId },
			Type = CampaignType.Regular
		}).Result;
		var timeStr = DateTime.Now.ToString();
		var content = _mailChimpManager.Content.AddOrUpdateAsync(
		 campaign.Id,
		 new ContentRequest()
		 {
			 Template = new ContentTemplate
			 {
				 Id = TemplateId,
				 Sections = new Dictionary<string, object>()
			{
	   { "body_content", html },
	   { "preheader_leftcol_content", $"<p>{timeStr}</p>" }
			}
			 }
		 }).Result;
		_mailChimpManager.Campaigns.SendAsync(campaign.Id).Wait();
	}
	public List<Template> GetAllTemplates()
	  => _mailChimpManager.Templates.GetAllAsync().Result.ToList();
	public List<List> GetAllMailingLists()
	  => _mailChimpManager.Lists.GetAllAsync().Result.ToList();
	public Content GetTemplateDefaultContent(string templateId)
  => (Content)_mailChimpManager.Templates.GetDefaultContentAsync(templateId).Result;
}