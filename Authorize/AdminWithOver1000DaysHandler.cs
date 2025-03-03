using IdentityManager.Services.IService;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentityManager.Authorize
{
    public class AdminWithOver1000DaysHandler : AuthorizationHandler<AdminWithMoreThan1000Days>
    {
        private readonly INumberofDaysForAccount _numberofDaysForAccount;
        public AdminWithOver1000DaysHandler(INumberofDaysForAccount numberofDaysForAccount) 
        {
            _numberofDaysForAccount = numberofDaysForAccount;
        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminWithMoreThan1000Days requirement)
        {
            if (!context.User.IsInRole(SD.Admin))
            {
                return Task.CompletedTask;
            }

            //this is an admin account
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var numberOfDays = _numberofDaysForAccount.Get(userId);
            
            if(numberOfDays >= requirement.Days)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
}
