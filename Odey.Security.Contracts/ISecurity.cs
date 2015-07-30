using System.Collections.Generic;
using System.ServiceModel;
using Odey.Framework.Keeley.Entities.Enums;

namespace Odey.Security.Contracts
{
    [ServiceContract(Namespace = "Odey.Security.Contracts")]
    public interface ISecurity
    {

        /// <summary>
        ///     Returns Dictionary with user's permissions and operations
        /// </summary>
        /// <param name="adName">Active Directory Name</param>
        /// <returns></returns>
        [OperationContract]
        Dictionary<FunctionPointIds, FunctionOperations> GetUserPermissionByADName(string adName);

        /// <summary>
        ///     Returns Dictionary with user's permissions and operations. Uses Call stack User Group or Windows if null
        /// </summary>
        /// <returns></returns>
        [OperationContract]
        Dictionary<FunctionPointIds, FunctionOperations> GetUserPermission();
    
    }
}
