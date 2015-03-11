// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNet.Authentication.Cookies.Compatibility;
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
            bool createShareableTickets = false)
        {
            // If we're asked to create shareable tickets, then we need to inject our own ticket formatter
            // that's compatible with ASP.NET 5.
            if (createShareableTickets)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    "Microsoft.AspNet.Authentication.Cookies.CookieAuthenticationMiddleware", // full name of the ASP.NET 5 type
                    options.AuthenticationType, "v2");
                options.TicketDataFormat = new AspNet5TicketDataFormat(dataProtector, options.AuthenticationType);
            }

            return app.UseCookieAuthentication(options, stage);
        }
    }
}
