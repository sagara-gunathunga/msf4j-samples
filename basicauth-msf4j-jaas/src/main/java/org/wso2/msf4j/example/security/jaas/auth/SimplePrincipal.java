package org.wso2.msf4j.example.security.jaas.auth;

import java.security.Principal;


public class SimplePrincipal implements Principal, java.io.Serializable {

    private String name;

    public SimplePrincipal(String name) {
        if (name == null)
            throw new NullPointerException("illegal null input");

        this.name = name;
    }


    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "SimplePrincipal{" +
                "name='" + name + '\'' +
                '}';
    }
}
