/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.systest.dispatch;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;

/**
 * Simple client key password callback sample class
 * 
 *
 */
public class ClientKeyPasswordCallback implements CallbackHandler {

    private static Map<String, String> passwords = new HashMap<String, String>();

    public ClientKeyPasswordCallback() {
        passwords.put("signer", "password");
        passwords.put("provider", "password");
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];

            String pass = passwords.get(pc.getIdentifier());
            if (pass != null) {
                pc.setPassword(pass);
                return;
            }
        }
    }

    /**
     * Overwrite password with environment specific value
     * 
     * @param alias    Key alias to private certificate
     * @param password Password to certificate in keystore
     */
    public static void addPassword(String alias, String password) {
        String oldPassword = passwords.get(alias);
        if (oldPassword != null && oldPassword.equals(password)) {
            return;
        }

        passwords.put(alias, password);
    }
}
