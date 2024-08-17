using Enterprise01.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace Enterprise01.Controllers
{
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;

        public UserController(ILogger<UserController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Authorize]
        public IActionResult Index()
        {


            if (this.HttpContext.User is ClaimsPrincipal)
            {
                var claimsPrincipal = (ClaimsPrincipal)this.HttpContext.User;
               
                var claimsPrinciples = claimsPrincipal.Identities;
                foreach (var item in claimsPrinciples)
                {
                    Debug.WriteLine($"{item.Name}");
                }

                var claims = claimsPrincipal.Claims;
                foreach (var item in claims)
                {
                    Debug.WriteLine($"{item.Value}");
                }
            }
            return View();
        }
    }
}
