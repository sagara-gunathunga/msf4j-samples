package org.wso2.msf4j.example.security.interceptor;

import org.wso2.msf4j.Interceptor;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.Response;
import org.wso2.msf4j.ServiceMethodInfo;
import org.wso2.msf4j.example.security.MSF4JSecurityContext;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

/**
 * Created by sagara on 11/17/16.
 */
public abstract class AbstractAuthenticationInterceptor implements Interceptor {

    @Override
    public boolean preCall(Request request, Response response, ServiceMethodInfo serviceMethodInfo) throws Exception {
        return handleAuthentication(request, response);
    }

    @Override
    public void postCall(Request request, int i, ServiceMethodInfo serviceMethodInfo) throws Exception {

    }

    protected abstract boolean handleAuthentication(Request request, Response response);

    protected void setSecurityContext(Principal principal, Request request) {
        SecurityContext securityContext = new MSF4JSecurityContext(principal, request.getUri(), request.getHttpMethod());
        request.setProperty("SECURITY_CONTEXT", securityContext);
    }
}
