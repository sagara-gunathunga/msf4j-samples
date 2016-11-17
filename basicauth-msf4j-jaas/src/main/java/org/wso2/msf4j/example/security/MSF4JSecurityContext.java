package org.wso2.msf4j.example.security;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

/**
 * Created by sagara on 11/17/16.
 */
public class MSF4JSecurityContext implements SecurityContext {

    private Principal principal;
    private String resourcePath;
    private String httpMethod;

    public MSF4JSecurityContext(Principal principal) {
        this.principal = principal;
    }

    public MSF4JSecurityContext(Principal principal, String resourcePath, String httpMethod) {
        this.principal = principal;
        this.resourcePath = resourcePath;
        this.httpMethod = httpMethod;
    }

    @Override
    public Principal getUserPrincipal() {
        return principal;
    }

    @Override
    public boolean isUserInRole(String role) {
        return false;
    }

    @Override
    public boolean isSecure() {
        return false;
    }

    @Override
    public String getAuthenticationScheme() {
        return null;
    }

    public Principal getPrincipal() {
        return principal;
    }


    public String getResourcePath() {
        return resourcePath;
    }


    public String getMethod() {
        return httpMethod;
    }

    @Override
    public String toString() {
        return "MSF4JSecurityContext{" +
                "principal=" + principal +
                ", resourcePath='" + resourcePath + '\'' +
                ", httpMethod='" + httpMethod + '\'' +
                '}';
    }
}
