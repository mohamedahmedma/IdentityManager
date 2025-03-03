using IdentityManager.Authorize;
using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Services;
using IdentityManager.Services.IService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

namespace IdentityManager
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddDbContext<AppDbContext>(options => 
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
            );

            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<AppDbContext>().AddDefaultTokenProviders();

            builder.Services.AddTransient<IEmailSender, EmailSender>();
            builder.Services.AddScoped<INumberofDaysForAccount, NumberOfDaysForAccount>();
            builder.Services.AddScoped<IAuthorizationHandler, AdminWithOver1000DaysHandler>();
            builder.Services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();

            builder.Services.ConfigureApplicationCookie(opt =>
            {
                opt.AccessDeniedPath = new PathString("/Account/NoAccess");
            });



            builder.Services.Configure<IdentityOptions>(opt =>
            {
                opt.Password.RequireDigit = false;
                opt.Password.RequireLowercase = false;
                opt.Password.RequiredUniqueChars = 0;
                opt.Lockout.MaxFailedAccessAttempts = 3;
                opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(3);
                opt.SignIn.RequireConfirmedEmail = false;
                //opt.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
            });

            builder.Services.AddAuthorization(op =>
            {
                op.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
                op.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
                op.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("Create" , "True"));
                op.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => policy
                .RequireRole(SD.Admin)
                .RequireClaim("Create" , "True")
                .RequireClaim("Edit" , "True")
                .RequireClaim("Delete" , "True") 
                );

                op.AddPolicy("AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole", policy => policy
                .RequireAssertion(context =>
                AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole(context)

                ));
                op.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));

                op.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000Days(1000)));

                op.AddPolicy("FirstNameAuth", policy => policy.Requirements.Add(new FirstNameAuthRequirement("test")));

            });

            //value == nOI8Q~1qmGSK8efv47Be-varygjOxZCOHvjK0bCW
            //ID = 413eb8c7-928d-4dc4-b994-4a4802aadede
            builder.Services.AddAuthentication().AddMicrosoftAccount(opt =>
            {
                opt.ClientId = "413eb8c7-928d-4dc4-b994-4a4802aadede";
                opt.ClientSecret = "nOI8Q~1qmGSK8efv47Be-varygjOxZCOHvjK0bCW";
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseRouting();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();

            bool AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole(AuthorizationHandlerContext context)
            {
                return (
                        context.User.IsInRole(SD.Admin) && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
                        )
                        || context.User.IsInRole(SD.SuperAdmin);
            }
        }
       
    }
}
