﻿using System.Collections.Generic;
using System.ServiceModel;
using Odey.Framework.Infrastructure.Clients;
using Odey.Framework.Keeley.Entities.Enums;
using Odey.Security.Contracts;

namespace Odey.Security.Clients
{
    public class SecurityClient : OdeyClientBase<ISecurity>, ISecurity
    {
        public Dictionary<FunctionPointIds, FunctionOperations> GetUserPermissionByADName(string adName)
        {
            Dictionary<FunctionPointIds, FunctionOperations> permissions = null;
            ISecurity proxy = factory.CreateChannel();
            try
            {
                permissions = proxy.GetUserPermissionByADName(adName);
                ((ICommunicationObject)proxy).Close();

            }
            catch
            {
                ((ICommunicationObject)proxy).Abort();
                throw;
            }

            return permissions;
        }

        public Dictionary<FunctionPointIds, FunctionOperations> GetUserPermission()
        {
            Dictionary<FunctionPointIds, FunctionOperations> permissions = null;
            ISecurity proxy = factory.CreateChannel();
            try
            {
                permissions = proxy.GetUserPermission();
                ((ICommunicationObject)proxy).Close();

            }
            catch
            {
                ((ICommunicationObject)proxy).Abort();
                throw;
            }

            return permissions;
        }

    
    }
}
