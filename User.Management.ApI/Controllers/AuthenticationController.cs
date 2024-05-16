using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NETCore.MailKit.Core;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.ApI.Models;
using User.Management.ApI.Models.Authentication.Login;
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
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ITestServiece _testServiece;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager,           
            ITestServiece testServiece, IConfiguration configuration)

        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _testServiece = testServiece;
            _configuration = configuration;

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
                UserName = registerUser.UserName,
                TwoFactorEnabled =true
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
                //Add token to verify the mail
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail),"Authentication", new {token,email=user.Email},Request.Scheme);
                var message = new Message(new string[] { user.Email }, "Confirmation email link", confirmationLink!);
                _testServiece.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                     new Response { Status = "Success", Message = $"User Created and email sent to {user.Email} Successfully" });
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
           
            //Assign a role
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
                { "ashikuzzaman18@gmail.com" }, "Test", "Hello you...");
            _testServiece.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Email Sent Successfully" });

        }
        [HttpGet("ConfirmEmail")]
        public async Task <IActionResult> ConfirmEmail (string token,string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            { 
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Email Verified Successfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "This user doesn't exist" });
        }

        //[HttpPost]
        //[Route("login")]
        //public async Task <ActionResult> Login([FromBody] Login login)
        //{
        //    //checking user
        //    var user =await _userManager.FindByNameAsync(login.UserName);
        //    if (user.TwoFactorEnabled)
        //    {
        //        await _signInManager.SignOutAsync();
        //        await _signInManager.PasswordSignInAsync(user, login.Password, false, true);
        //        var token = await _userManager.GenerateTwoFactorTokenAsync(user,"Email");
        //        var message = new Message(new string[] { user.Email }, "OTP Confirmation", token);
        //        _testServiece.SendEmail(message);
        //        return StatusCode(StatusCodes.Status200OK,
        //       new Response { Status = "Success", Message = $"We have sent an OTP to your Email: {user.Email}" });
        //    }
        //    if (user != null && await _userManager.CheckPasswordAsync(user,login.Password))
        //    {
        //        var authClaims = new List<Claim>
        //        {
        //          new Claim(ClaimTypes.Name, user.UserName),
        //          new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //        };
        //        var userRoles = await _userManager.GetRolesAsync(user);
        //        foreach (var role in userRoles)
        //        {
        //            authClaims.Add(new Claim(ClaimTypes.Role, role));
        //        }

        //        var jwtToken =GetToken (authClaims);

        //        return Ok(new
        //        {
        //            token =new JwtSecurityTokenHandler ().WriteToken(jwtToken),
        //            expiration =jwtToken.ValidTo
        //        });
        //    }
        //    return Unauthorized();
        //    //check password
        //    //claim list creation
        //    //add role to the user
        //}
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            var user = await _userManager.FindByNameAsync(login.UserName);
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, login.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email! }, "OTP Confrimation", token);
                _testServiece.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                 new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
            }
            if (user != null && await _userManager.CheckPasswordAsync(user, login.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }


                var jwtToken = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                });
                //returning the token...

            }
            return Unauthorized();


        }
        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtToken = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });
                    //returning the token...

                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }
      

        private JwtSecurityToken GetToken (List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires:DateTime.Now.AddHours(3),
                claims:authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}
