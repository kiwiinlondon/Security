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
using System.Data.SqlTypes;
using System.DirectoryServices.AccountManagement;
using System.Reflection;
using System.Runtime.Caching;
using log4net;
using log4net.Repository.Hierarchy;

namespace Odey.Security
{
    public static class Security 
    {
        private static readonly ILog logger = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

     
        public static Dictionary<FunctionPointIds, FunctionOperations> GetUserPermissionByADName(string adName)
        {
            logger.DebugFormat("Get User Permission: {0}", adName);

            // Check Cache for permissions
            var permissionsCached = GetObjectFromCache(adName);
            if (permissionsCached != null)
            {
                return permissionsCached;
            }

            var permissions = new Dictionary<FunctionPointIds, FunctionOperations>();

            using (KeeleyModel context = new KeeleyModel(SecurityCallStackContext.Current))
            {

                List<string> usersGroups = GetGroupsForUserName(adName);
                
                // Get all Security Groups for that user
                var securityGroupsIds = context.SecurityGroups.Where(sg => usersGroups.Any( group => group == sg.ADName)).Select( group => group.SecurityGroupId);

                if (securityGroupsIds == null)
                {
                    return permissions;
                }

                var userFunctionPoints = context.SecurityGroupFunctionPoints.Where( fp => securityGroupsIds.Any( groupId => groupId == fp.SecurityGroupId ) );

                foreach (var functionPoint in userFunctionPoints)
                {
                    FunctionPointIds fp = (FunctionPointIds) functionPoint.FunctionPointId;

                    // If Function Point exist. Add New Permissions (If User belong to 2 groups we need and Or of both permissions
                    if (permissions.ContainsKey(fp))
                    {
                        FunctionOperations operations = permissions[fp];

                        // Add new Permissions
                        if (functionPoint.CreatePermission && !operations.HasFlag(FunctionOperations.Create))
                        {
                            operations |= FunctionOperations.Create;
                        }
                        if (functionPoint.ReadPermission && !operations.HasFlag(FunctionOperations.Read))
                        {
                            operations |= FunctionOperations.Read;
                        }
                        if (functionPoint.UpdatePermission && !operations.HasFlag(FunctionOperations.Update))
                        {
                            operations |= FunctionOperations.Update;
                        }
                        if (functionPoint.DeletePermission && !operations.HasFlag(FunctionOperations.Delete))
                        {
                            operations |= FunctionOperations.Delete;
                        }

                        permissions[fp] = operations;
                    }
                    else
                    {
                        FunctionOperations ops = FunctionOperations.None;
                        if (functionPoint.CreatePermission)
                        {
                            ops |= FunctionOperations.Create;
                        }

                        if (functionPoint.ReadPermission)
                        {
                            ops |= FunctionOperations.Read;
                        }

                        if (functionPoint.UpdatePermission)
                        {
                            ops |= FunctionOperations.Update;
                        }

                        if (functionPoint.DeletePermission)
                        {
                            ops |= FunctionOperations.Delete;
                        }

                        permissions.Add(fp, ops);

                    }
                }

                SaveToCache(adName, permissions);
                return permissions;
            }
        }

      


        public static Dictionary<FunctionPointIds, FunctionOperations> GetUserPermission()
        {
            string userName = GetUserName();

            return GetUserPermissionByADName(userName);
        }

        public static FunctionOperations GetUserPermissionForFunction(FunctionPointIds function)
        {
            var permissions = GetUserPermission();

            if (permissions.ContainsKey(function))
            {
                return permissions[function];
            }

            return FunctionOperations.None;
        }

        public static bool IsUserOperationAllowed(FunctionPointIds function, FunctionOperations operations)
        {
            var allowedOperations = GetUserPermissionForFunction(function);

            return allowedOperations.HasFlag(operations);

        }

        private static void SaveToCache(string adName, Dictionary<FunctionPointIds, FunctionOperations> permissions)
        {
            ObjectCache cache = MemoryCache.Default;

            string sql = String.Format("SELECT * FROM dbo.SecurityGroupFunctionPoint");

            cache.Set(adName, permissions, Odey.Framework.Infrastructure.Utilities.CacheItemPolicyHelper.GetForSql(sql));
        }

        private static Dictionary<FunctionPointIds, FunctionOperations> GetObjectFromCache(string adName)
        {
            ObjectCache cache = MemoryCache.Default;

            if (cache.Contains(adName))
            {
                return (Dictionary<FunctionPointIds, FunctionOperations>)cache.Get(adName);
            }

            return null;
        }

        private static string GetUserName()
        {
            var callStack = SecurityCallStackContext.Current;
            SecurityCallFrame callFrame = null;
            if (callStack != null)
            {
                callFrame = callStack.OriginalCall;
            }
            string userName;
            if (callFrame == null)
            {
                // Debug Locahost
                userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            }
            else
            {
                userName = callFrame.IdentityName;
            }
            return userName;
        }

        private static List<string> GetGroupsForUserName(string adName)
        {
            List<string> groupNames = new List<string>();

            var pc = new PrincipalContext(ContextType.Domain, "OAM.ODEY.COM");
            UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(pc, adName);

            if (userPrincipal != null)
            {
                var groups = userPrincipal.GetAuthorizationGroups();
                // iterate over all groups
                foreach (Principal p in groups)
                {
                    // make sure to add only group principals
                    if (p is GroupPrincipal)
                    {
                        groupNames.Add( p.SamAccountName );
                    }
                }
            }
            return groupNames;
        }
    }
}
