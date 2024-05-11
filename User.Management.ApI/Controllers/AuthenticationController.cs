using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NETCore.MailKit.Core;
using User.Management.ApI.Models;
using User.Management.ApI.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Services;

namespace User.Management.ApI.Controllers
{
    [Route("api/controller")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ITestServiece _testServiece;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager,           
            ITestServiece testServiece)
        
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _testServiece = testServiece;
        }
        [HttpPost]

        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            //check user exist
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exist" });
            }
            //Add user if not
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName
            };
            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                      new Response { Status = "Error", Message = "User failed to create" });
                }
                //add role to user
                await _userManager.AddToRoleAsync(user, role);

                return StatusCode(StatusCodes.Status200OK,
                     new Response { Status = "Error", Message = "User Create Successfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                     new Response { Status = "Error", Message = "This role doesn't exist" });
            }
            
            //return result.Succeeded
            
            //  ? StatusCode(StatusCodes.Status201Created,
            //         new Response { Status = "Success", Message = "User Created Successfully" })
          
            //   : StatusCode(StatusCodes.Status500InternalServerError,
            //      new Response { Status = "Error", Message = "User failed to create" });
           
            //Assaign a role
        }
        //public IActionResult Index()
        //{
        //    return View();
        //}
        [HttpGet]
        public IActionResult TestEmail()
        {
            var message =
             new Message(new string[]
                { "receiver mail" }, "Test", "Hello you...");
            _testServiece.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Email Sent Successfully" });

        }
    }
}
