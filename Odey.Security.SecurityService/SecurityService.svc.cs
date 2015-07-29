using System.Collections.Generic;
using Odey.Framework.Infrastructure.Services;
using Odey.Framework.Keeley.Entities.Enums;
using Odey.Security.Contracts;

namespace Odey.Security.SecurityService
{

    public class SecurityService : OdeyServiceBase, ISecurity
    {
        private readonly Security security;
        public SecurityService()
        {
            security = new Security();
        }

        public Dictionary<FunctionPointIds, FunctionOperations> GetUserPermission(string adName)
        {
            return security.GetUserPermission(adName);
        }
    }
}
