/*
 * Copyright (c) 2016, WSO2 Inc. (http://wso2.com) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.msf4j.example.security.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.Response;
import org.wso2.msf4j.example.security.jaas.auth.SimplePrincipal;
import org.wso2.msf4j.example.security.jaas.auth.WebCallbackHandler;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;

/**
 * A simple security interceptor which handled username/password based authentication
 */
public class BasicAuthJAASInterceptor extends AbstractAuthenticationInterceptor {

    private static final Logger log = LoggerFactory.getLogger(BasicAuthJAASInterceptor.class);

    protected boolean handleAuthentication(Request request, Response response) {
        LoginContext lc = getLoginContext(request);
        try {
            lc.login();
            Subject subject = lc.getSubject();
            for (Principal principal : subject.getPrincipals()) {
                if (principal instanceof SimplePrincipal) {
                    setSecurityContext(principal, request);
                    return true;
                }
            }
        } catch (LoginException e) {
            handleLoginError(response, e);
        }
        return false;
    }

    private void handleLoginError(Response response, LoginException e) {
        log.error("Authentication Error ", e);
        response.setStatus(javax.ws.rs.core.Response.Status.UNAUTHORIZED.getStatusCode());
        response.setHeader(javax.ws.rs.core.HttpHeaders.WWW_AUTHENTICATE, WebCallbackHandler.AUTH_TYPE_BASIC);
        response.send();
    }

    private static LoginContext getLoginContext(Request request) {
        try {
            return new LoginContext("Web", new WebCallbackHandler(request));
        } catch (LoginException | SecurityException le) {
            log.error("Cannot create LoginContext ", le);
        }
        return null;
    }


}
