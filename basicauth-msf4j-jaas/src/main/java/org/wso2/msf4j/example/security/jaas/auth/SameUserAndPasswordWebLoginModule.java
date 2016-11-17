package org.wso2.msf4j.example.security.jaas.auth;


/**
 * Created by sagara on 10/28/16.
 */


import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.Map;


public class SameUserAndPasswordWebLoginModule implements LoginModule {

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;

    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    private String username;
    private char[] password;

    private SimplePrincipal userPrincipal;


    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
    }

    public boolean login() throws LoginException {

        //Setup Callbacks
        NameCallback nameCallback = new NameCallback("username");
        PasswordCallback passwordCallback = new PasswordCallback("password: ", false);

        //Handle Callbacks
        try {
            callbackHandler.handle(new Callback[]{nameCallback, passwordCallback});
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnsupportedCallbackException e) {
            throw new LoginException("Error: " + e.getCallback().toString() +
                    " not available to garner authentication information " +
                    "from the user");
        }

        //Process Callbacks results
        username = nameCallback.getName();
        password = passwordCallback.getPassword();
        passwordCallback.clearPassword();

        //Login logic
        if (username.equals(new String(password))) {
            succeeded = true;
            return true;
        } else {
            throw new LoginException("User Name Incorrect");
        }

    }


    public boolean commit() throws LoginException {
        if (succeeded) {
            // add a Principal (authenticated identity)
            // to the Subject

            // assume the user we authenticated is the SimplePrincipal
            userPrincipal = new SimplePrincipal(username);
            if (!subject.getPrincipals().contains(userPrincipal))
                subject.getPrincipals().add(userPrincipal);

            // in any case, clean out state
            username = null;
            for (int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;

            commitSucceeded = true;
            return true;

        }
        return false;
    }


    public boolean abort() throws LoginException {
        if (succeeded == false) {
            return false;
        } else if (succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
            username = null;
            if (password != null) {
                for (int i = 0; i < password.length; i++)
                    password[i] = ' ';
                password = null;
            }
            userPrincipal = null;
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    public boolean logout() throws LoginException {

        subject.getPrincipals().remove(userPrincipal);
        succeeded = false;
        succeeded = commitSucceeded;
        username = null;
        if (password != null) {
            for (int i = 0; i < password.length; i++)
                password[i] = ' ';
            password = null;
        }
        userPrincipal = null;
        return true;
    }
}
