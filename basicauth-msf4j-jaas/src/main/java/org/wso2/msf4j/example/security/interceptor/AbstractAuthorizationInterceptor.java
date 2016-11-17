package org.wso2.msf4j.example.security.interceptor;

import org.wso2.msf4j.Interceptor;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.Response;
import org.wso2.msf4j.ServiceMethodInfo;

import javax.ws.rs.core.SecurityContext;

/**
 * Created by sagara on 11/17/16.
 */
public class AbstractAuthorizationInterceptor implements Interceptor {

    @Override
    public boolean preCall(Request request, Response response, ServiceMethodInfo serviceMethodInfo) throws Exception {
        System.out.println("SECURITY_CONTEXT " + getSecurityContext(request));
//        return handleAuthentication(request, response);
        return true;
    }

    @Override
    public void postCall(Request request, int i, ServiceMethodInfo serviceMethodInfo) throws Exception {

    }


    protected SecurityContext getSecurityContext(Request request) {
        return (SecurityContext) request.getProperty("SECURITY_CONTEXT");
    }
}
