using Microsoft.AspNetCore.Authorization;

namespace IdentityManager.Authorize
{
    public class AdminWithMoreThan1000Days : IAuthorizationRequirement
    {
        public int Days { get; set; }
        public AdminWithMoreThan1000Days(int days)
        {
            Days = days;
        }
    }
}
