using System.Collections.Generic;
using Odey.Framework.Infrastructure.Services;
using Odey.Framework.Keeley.Entities.Enums;
using Odey.Security.Contracts;

namespace Odey.Security.SecurityService
{

    public class SecurityService : OdeyServiceBase, ISecurity
    {
      

        public Dictionary<FunctionPointIds, FunctionOperations> GetUserPermissionByADName(string adName)
        {
            return Security.GetUserPermissionByADName(adName);
        }

        public Dictionary<FunctionPointIds, FunctionOperations> GetUserPermission()
        {
            return Security.GetUserPermission();
        }

        public FunctionOperations GetUserPermissionForFunction(FunctionPointIds function)
        {
            return Security.GetUserPermissionForFunction(function);
        }

        public bool IsUserOperationAllowed(FunctionPointIds function, FunctionOperations operations)
        {
            return Security.IsUserOperationAllowed(function, operations);
        }
    }
}
