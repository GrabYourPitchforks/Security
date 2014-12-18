// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Framework.OptionsModel;

namespace Microsoft.AspNet.Security
{
    public class DefaultAuthorizationService : IAuthorizationService
    {
        private readonly IList<IAuthorizationPolicyHandler> _handlers;
        private readonly AuthorizationOptions _options;

        public DefaultAuthorizationService(IOptions<AuthorizationOptions> options, IEnumerable<IAuthorizationPolicyHandler> handlers = null)
        {
            if (handlers == null)
            {
                _handlers = new List<IAuthorizationPolicyHandler>();
            }
            else
            {
                _handlers = handlers.ToArray(); // REVIEW: order?
            }
            _options = options.Options;
        }

        public Task<bool> AuthorizeAsync([NotNull] string policyName, ClaimsPrincipal user, params object[] resources)
        {
            var policy = _options.GetPolicy(policyName);
            if (policy == null)
            {
                return Task.FromResult(false);
            }
            return AuthorizeAsync(policy, user, resources);
        }

        public async Task<bool> AuthorizeAsync([NotNull] IAuthorizationPolicy policy, ClaimsPrincipal user, params object[] resources)
        {
            // Authorize only returns true if EVERY policy handler approves
            var context = new AuthorizationContext(policy, user, resources);
            // Run global handlers first
            foreach (var handler in _handlers)
            {
                if (!await handler.AuthorizeAsync(context))
                {
                    return false;
                }
            }
            // Check policy requirements next
            if (policy.Requirements != null)
            {
                foreach (var req in policy.Requirements)
                {
                    if (!await req.CheckAsync(context))
                    {
                        return false;
                    }
                }
            }
            return true;
        }
    }
}