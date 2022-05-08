using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RestSample.Controllers
{
    [Route("api/app")]
    public class AppController : ControllerBase
    {
        [Route("token"), HttpGet]
        public IActionResult Authenticate()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("this is my custom Secret key for authentication");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, "this is my custom Secret key for authentication")
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var customToken = tokenHandler.WriteToken(token);

            return Ok(customToken);
        }

        [Authorize]
        [Route("secure_data"), HttpGet]
        public IActionResult SecureData()
        {
            return Ok("Token ile yapılan istek başarılı.");
        }
    }
}
