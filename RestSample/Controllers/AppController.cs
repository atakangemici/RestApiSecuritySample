using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using RestSample.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace RestSample.Controllers
{
    [Route("api/app")]
    public class AppController : ControllerBase
    {
        private IConfiguration Configuration;

        public AppController(IConfiguration _configuration)
        {
            Configuration = _configuration;
        }

        [Route("token"), HttpPost]
        public IActionResult GetToken([FromBody] UserModel user)
        {
            if (user.Name == "atakan" && user.Password == "11aa22bb33")
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
            else
            {
                return BadRequest("Token yetkilendirilmesi için girdiğiniz kullanıcı bilgileri hatalı !");
            }
        }

        [Authorize]
        [Route("secure_data_with_token"), HttpGet]
        public IActionResult SecureDataWithToken()
        {
            return Ok("Token yetkilendirilmesi ile yapılan istek başarılı.");
        }

        [Route("secure_data_with_restriction"), HttpGet]
        public IActionResult SecureDataWithRestriction()
        {
            string ipSafeList = this.Configuration.GetSection("AppSettings")["IPSafeList"];
            var remoteIpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            if (ipSafeList == remoteIpAddress)
                return Ok("IP adresiniz güvenli IP adresi listesinde , istek başarılı.");
            else
                return BadRequest("IP adresiniz güvenli IP adresi listesinde ekli değil , istek başarısız !");
        }

        [Authorize]
        [Route("secure_data_with_restriction_and_token"), HttpGet]
        public IActionResult SecureDataWithRestrictionAndToken()
        {
            string ipSafeList = this.Configuration.GetSection("AppSettings")["IPSafeList"];
            var remoteIpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            if (ipSafeList == remoteIpAddress)
                return Ok("Token yetkilendirilmesi geçerli ve IP adresiniz güvenli IP adresi listesinde , istek başarılı.");
            else
                return BadRequest("IP adresiniz güvenli IP adresi listesinde ekli değil , istek başarısız !");
        }
    }
}
