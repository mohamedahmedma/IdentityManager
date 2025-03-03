using IdentityManager.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
namespace IdentityManager.Data
{
    public class AppDbContext : IdentityDbContext
    {
        public DbSet<ApplicationUser> ApplicationUsers {  get; set; }
        public AppDbContext(DbContextOptions options) : base(options)
        {

        }
    }
}
