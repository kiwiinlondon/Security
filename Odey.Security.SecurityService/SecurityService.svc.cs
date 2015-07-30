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

        public Dictionary<FunctionPointIds, FunctionOperations> GetUserPermissionByADName(string adName)
        {
            return security.GetUserPermissionByADName(adName);
        }

        public Dictionary<FunctionPointIds, FunctionOperations> GetUserPermission()
        {
            return security.GetUserPermission();
        }

        public FunctionOperations GetUserPermissionForFunction(FunctionPointIds function)
        {
            return security.GetUserPermissionForFunction(function);
        }

        public bool IsUserOperationAllowed(FunctionPointIds function, FunctionOperations operations)
        {
            return security.IsUserOperationAllowed(function, operations);
        }
    }
}
