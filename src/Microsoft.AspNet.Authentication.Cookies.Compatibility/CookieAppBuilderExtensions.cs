// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNet.Authentication.Cookies.Compatibility;
using Microsoft.AspNet.DataProtection.SystemWeb;
using Microsoft.Framework.Internal;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;

namespace Owin
{
    public static class CookieAuthenticationExtensions
    {
        public static IAppBuilder UseCookieAuthentication(
            [NotNull] this IAppBuilder app,
            [NotNull] CookieAuthenticationOptions options,
            PipelineStage stage = PipelineStage.Authenticate,
            bool createShareableTickets = false,
            string authenticationScheme = null)
        {
            // If we're asked to create shareable tickets, then we need to inject our own ticket formatter
            // that's compatible with ASP.NET 5.
            if (createShareableTickets)
            {
                // In ASP.NET 5 cookie middleware and identity, there's a distinction between auth scheme
                // (of which there's one per cookie / ticket) and auth type (of which there's one per identity).
                // We'll try to perform auto-fixup here by using the defaults.
                if (authenticationScheme == null)
                {
                    if ((options.AuthenticationType?.EndsWith(".AuthType", StringComparison.OrdinalIgnoreCase)).GetValueOrDefault())
                    {
                        authenticationScheme = options.AuthenticationType.Substring(0, options.AuthenticationType.Length - ".AuthType".Length);
                    }
                    else
                    {
                        authenticationScheme = options.AuthenticationType;
                    }
                }

                IDataProtector dataProtector = app.CreateDataProtector(
                    "Microsoft.AspNet.Authentication.Cookies.CookieAuthenticationMiddleware", // full name of the ASP.NET 5 type
                    authenticationScheme, "v2");
                dataProtector = new WrappingDataProtector(dataProtector);
                options.TicketDataFormat = new AspNet5TicketDataFormat(dataProtector, authenticationScheme);
            }

            return app.UseCookieAuthentication(options, stage);
        }

        private sealed class WrappingDataProtector : IDataProtector
        {
            private readonly IDataProtector _innerProtector;

            public WrappingDataProtector(IDataProtector innerProtector)
            {
                _innerProtector = innerProtector;
            }

            public byte[] Protect(byte[] userData)
            {
                return CompatibilityDataProtector.RunWithSuppressedPrimaryPurpose(
                    (@this, input) => ((IDataProtector)@this).Protect(input),
                    _innerProtector, userData);
            }

            public byte[] Unprotect(byte[] protectedData)
            {
                return CompatibilityDataProtector.RunWithSuppressedPrimaryPurpose(
                    (@this, input) => ((IDataProtector)@this).Unprotect(input),
                    _innerProtector, protectedData);
            }
        }
    }
}
