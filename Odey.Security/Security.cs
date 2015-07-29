using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Odey.Framework.Infrastructure.Services;
using Odey.Framework.Keeley.Entities;
using Odey.Framework.Keeley.Entities.Enums;
using Odey.Security.Contracts;
using ServiceModelEx;
using System.Data.Entity;
using System.Reflection;
using log4net;
using log4net.Repository.Hierarchy;

namespace Odey.Security
{
    public class Security : ISecurity
    {
        private readonly ILog logger;

        public Security()
        {
            logger = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        }

        public Dictionary<FunctionPointIds,FunctionOperations> GetUserPermission(string adName)
        {
            logger.DebugFormat("Get User Permission: {0}", adName);

            var permissions = new Dictionary<FunctionPointIds, FunctionOperations>();

            using (KeeleyModel context = new KeeleyModel(SecurityCallStackContext.Current))
            {

                var securityG = context.SecurityGroups.SingleOrDefault( sg => sg.ADName == adName);

                if (securityG == null)
                {
                    return permissions;
                }

                var functionsPoints = context.SecurityGroupFunctionPoints.Where(sg => sg.SecurityGroupId == securityG.SecurityGroupId).ToList();

                foreach (var functions in functionsPoints)
                {
                    FunctionOperations ops = FunctionOperations.None;
                    if (functions.CreatePermission)
                    {
                        ops |= FunctionOperations.Create;
                    }

                    if (functions.ReadPermission)
                    {
                        ops |= FunctionOperations.Read;
                    }

                    if (functions.UpdatePermission)
                    {
                        ops |= FunctionOperations.Update;
                    }

                    if (functions.DeletePermission)
                    {
                        ops |= FunctionOperations.Delete;
                    }

                    permissions.Add((FunctionPointIds) functions.FunctionPointId, ops);
                }

                return permissions;
            }
        }
    }
}
