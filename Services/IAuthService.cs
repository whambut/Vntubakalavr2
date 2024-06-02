using System.Threading.Tasks;
using UserAuthApi.Models;

namespace UserAuthApi.Services
{
    public interface IAuthService
    {
        Task<string> Register(User user, string password);
        Task<string> Login(string username, string password);
        Task<bool> UserExists(string username);
    }
}