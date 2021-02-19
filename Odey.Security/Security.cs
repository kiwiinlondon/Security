using System;
using System.Collections.Generic;
using System.Linq;
using Odey.Framework.Keeley.Entities;
using Odey.Framework.Keeley.Entities.Enums;
using ServiceModelEx;
using System.DirectoryServices.AccountManagement;
using System.Reflection;
using System.Runtime.Caching;
using log4net;

namespace Odey.Security
{
    public static class Security 
    {
        private static readonly ILog logger = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

     
        public static Dictionary<FunctionPointIds, FunctionOperations> GetUserPermissionByADName(string adName)
        {
            adName = adName.ToUpper();
            logger.DebugFormat("Get User Permission: {0}", adName);

            ObjectCache cache = MemoryCache.Default;


            // Check Cache for permissions
            var permissionsCached = GetObjectFromCache(adName, cache);
            if (permissionsCached != null)
            {
                return permissionsCached;
            }

            var permissions = new Dictionary<FunctionPointIds, FunctionOperations>();

            using (KeeleyModel context = new KeeleyModel(SecurityCallStackContext.Current))
            {

                List<string> usersGroups = GetGroupsForUserName(adName);
                

                var userFunctionPoints = context.SecurityGroupFunctionPoints.Where(fp => usersGroups.Any( gr => gr == fp.SecurityGroup.ADName)).ToList();

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

                SaveToCache(adName, permissions, cache);
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

        private static void SaveToCache(string adName, Dictionary<FunctionPointIds, FunctionOperations> permissions, ObjectCache cache)
        {
            string sql = String.Format("SELECT CreatePermission, ReadPermission, UpdatePermission, DeletePermission FROM dbo.SecurityGroupFunctionPoint");

            cache.Set(adName, permissions, Odey.Framework.Infrastructure.Utilities.CacheItemPolicyHelper.GetForSql(sql));
        }

        private static Dictionary<FunctionPointIds, FunctionOperations> GetObjectFromCache(string adName, ObjectCache cache)
        {
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

        private static readonly List<string>  groupsToReturn = new List<string> {"OU=Intranet"};

        public static List<string> GetGroupsForUserName(string adName)
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
                    if (p is GroupPrincipal && !string.IsNullOrEmpty(p.DistinguishedName) && groupsToReturn.Any(g => p.DistinguishedName.Contains(g)))
                    {
                        groupNames.Add( p.SamAccountName );
                    }
                }
            }
            return groupNames;
        }

        public static Dictionary<int, FunctionOperations> GetUserPermissionsForEntities(EntityTypeIds entityType, IEnumerable<int> ids)
        {
            ids = ids.Distinct();


            if (entityType == EntityTypeIds.Fund)
            {
                // Admin users restricted for testing
                if (GetUserName().ToLower().EndsWith("_admin"))
                {
                    var allowed = new Dictionary<FundIds, bool> {
                        { FundIds.OUAR, true },
                        { FundIds.ARFF, true },
                        { FundIds.KELT, true },
                        { FundIds.DEVM, true },
                        { FundIds.FDXH, true },
                        { FundIds.RAFO, true },
                    };
                    return ids.ToDictionary(id => id, id => allowed.ContainsKey((FundIds)id) ? FunctionOperations.Read : FunctionOperations.None);
                }
                return ids.ToDictionary(id => id, id => FunctionOperations.Read);
            }
            else if (entityType == EntityTypeIds.Book)
            {
                return ids.ToDictionary(id => id, id => FunctionOperations.Read);
            }
            else
            {
                throw new NotImplementedException($"{entityType} permissions are not implemented");
            }
        }
    }
}
