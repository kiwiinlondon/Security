using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Odey.Framework.Keeley.Entities.Enums;
using Odey.Security.Clients;
using ServiceModelEx;

namespace Odey.Security.Testing
{
    class Program
    {
        static void Main(string[] args)
        {



            var security = Security.GetGroupsForUserName(@"OAM\carlosr");

            //var a = security.GetUserPermission();
        }
    }
}
