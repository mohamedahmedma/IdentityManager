using IdentityManager.Data;
using IdentityManager.Services.IService;

namespace IdentityManager.Services
{
    public class NumberOfDaysForAccount : INumberofDaysForAccount
    {
        private readonly AppDbContext _context;

        public NumberOfDaysForAccount(AppDbContext context)
        {
            _context = context;
        }
        public int Get(string userId)
        {
            var user = _context.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if(user != null && user.DateCreated != DateTime.MinValue)
            {
                return (DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}
