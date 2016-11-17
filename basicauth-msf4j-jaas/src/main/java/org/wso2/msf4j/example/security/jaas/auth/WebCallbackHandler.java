package org.wso2.msf4j.example.security.jaas.auth;

import org.wso2.msf4j.Request;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;

/**
 * Created by sagara on 11/16/16.
 */
public class WebCallbackHandler implements CallbackHandler {

    public static final String AUTH_TYPE_BASIC = "Basic";
    public static final String CHARSET_UTF_8 = "UTF-8";
    public static final int AUTH_TYPE_BASIC_LENGTH = AUTH_TYPE_BASIC.length();

    private String userName;
    private String password;

    public WebCallbackHandler(Request request) {
        String authHeader = request.getHeader(javax.ws.rs.core.HttpHeaders.AUTHORIZATION);
        if (authHeader != null) {
            String authType = authHeader.substring(0, AUTH_TYPE_BASIC_LENGTH);
            String authEncoded = authHeader.substring(AUTH_TYPE_BASIC_LENGTH).trim();
            if (AUTH_TYPE_BASIC.equals(authType) && !authEncoded.isEmpty()) {
                byte[] decodedByte = authEncoded.getBytes(Charset.forName(CHARSET_UTF_8));
                String authDecoded = new String(Base64.getDecoder().decode(decodedByte),
                        Charset.forName(CHARSET_UTF_8));
                String[] authParts = authDecoded.split(":");
                userName = authParts[0];
                password = authParts[1];
            }
        }
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof NameCallback) {
                NameCallback nameCall = (NameCallback) callbacks[i];
                nameCall.setName(userName);
            } else if (callbacks[i] instanceof PasswordCallback) {
                PasswordCallback passCall = (PasswordCallback) callbacks[i];
                passCall.setPassword(password.toCharArray());
            } else {
                throw new UnsupportedCallbackException(callbacks[i],
                        "The CallBacks are unrecognized in class: " + getClass().
                                getName());
            }
        }
    }
}
