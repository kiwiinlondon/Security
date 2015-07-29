using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Odey.Security.Clients;

namespace Odey.Security.Testing
{
    class Program
    {
        static void Main(string[] args)
        {

            var security = new Security();

            var a = security.GetUserPermission(@"OAM\Intranet_Programmers2");
        }
    }
}
