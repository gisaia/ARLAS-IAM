/*
 * Licensed to Gisaïa under one or more contributor
 * license agreements. See the NOTICE.txt file distributed with
 * this work for additional information regarding copyright
 * ownership. Gisaïa licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.arlas.iam.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.iam.exceptions.InvalidTokenException;
import io.arlas.iam.model.LoginSession;
import io.arlas.iam.model.User;
import org.hibernate.SessionFactory;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class TokenManager {
    private Algorithm algorithm;
    private JWTVerifier jwtVerifier;
    private final long accessTokenTTL;
    private final long refreshTokenTTL;
    private final ArlasAuthConfiguration authConf;
    public RSAPublicKey publicKey;


    public TokenManager(SessionFactory factory, ArlasAuthConfiguration configuration) throws ArlasException {
        this.accessTokenTTL = configuration.accessTokenTTL;
        this.refreshTokenTTL = configuration.refreshTokenTTL;
        this.authConf = configuration;
        this.initKeys();
    }

    private void initKeys() throws ArlasException {
            // try to load RSA keys from a PKCS12 keystore specified by system properties:
            // - javax.net.ssl.trustStore
            // - javax.net.ssl.trustStorePassword
            // - token.keyAlias
            try {
                String jksPath = System.getProperty("javax.net.ssl.trustStore");
                String jksPass = System.getProperty("javax.net.ssl.trustStorePassword");
                String alias = System.getProperty("token.keyAlias");
                if(jksPath == null) {
                    throw new ArlasException("TrustStore path is missing. Please check -Djavax.net.ssl.trustStore value.");
                }
                if(jksPass == null) {
                    throw new ArlasException("TrustStore password is missing. Please check -Djavax.net.ssl.trustStorePassword value.");
                }
                if(alias == null) {
                    throw new ArlasException("Key alias is missing. Please check -Dtoken.keyAlias value.");
                }
                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (InputStream is = Files.newInputStream(Path.of(jksPath))) {
                    ks.load(is, jksPass.toCharArray());
                } catch (IOException e) {
                    throw new ArlasException("Error reading and loading TrustStore from provided path :" + jksPath);
                }
                Key key = ks.getKey(alias, jksPass.toCharArray());
                if (key instanceof RSAPrivateKey privateKey) {
                    java.security.cert.Certificate cert = ks.getCertificate(alias);
                    if (cert != null && cert.getPublicKey() instanceof RSAPublicKey pKey) {
                        this.publicKey = pKey;
                        this.algorithm = Algorithm.RSA256(pKey, privateKey);
                        this.jwtVerifier = JWT.require(this.algorithm).acceptLeeway(3).build();
                    } else {
                        throw new ArlasException("Error with public key from TrustStore. Please check the alias and password provided.");
                    }
                } else {
                    throw new ArlasException("Error with private key from TrustStore. Please check the alias and password provided.");
                }
            } catch ( KeyStoreException | NoSuchAlgorithmException | CertificateException |
                     UnrecoverableKeyException e) {
                     throw new ArlasException("Error with provided TrustStore, password and alias.");
            }
    }

    public DecodedJWT verifyToken(String token)  {
        return jwtVerifier.verify(token);
    }

    public LoginSession getLoginSession(User subject, String issuer, Date iat) throws ArlasException {
        return new LoginSession(subject, createAccessToken(subject, issuer, iat),
                createRefreshToken(), (iat.getTime() + this.refreshTokenTTL)/1000);
    }

    public String createPermissionToken(String subject, String issuer, Date iat, Set<String> permissions, Map<String, List<String>> roles) throws ArlasException {
        try {
            Date exp = new Date(iat.getTime() + this.accessTokenTTL);
            JWTCreator.Builder builder = JWT.create()
                    .withKeyId("arlas")
                    .withIssuer(issuer)
                    .withSubject(subject)
                    .withIssuedAt(iat)
                    .withExpiresAt(exp)
                    .withClaim(this.authConf.claimPermissions, permissions.stream().toList())
                    .withClaim(this.authConf.claimRoles, roles);
            return builder.sign(this.algorithm);
        } catch (JWTCreationException exception){
            throw new ArlasException("Invalid Signing configuration / Couldn't convert Claims.");
        }
    }

    private String createAccessToken(User subject, String issuer, Date iat) throws ArlasException {
        try {
            Date exp = new Date(iat.getTime() + this.accessTokenTTL);
            return JWT.create()
                    .withIssuer(issuer)
                    .withKeyId("arlas")
                    .withSubject(subject.getId().toString())
                    .withIssuedAt(iat)
                    .withExpiresAt(exp)
                    .withClaim("http://arlas.io/locale", subject.getLocale())
                    .withClaim("http://arlas.io/timezone", subject.getTimezone())
                    .withClaim("email", subject.getEmail())
                    .sign(this.algorithm);
        } catch (JWTCreationException exception){
            throw new InvalidTokenException("Invalid Signing configuration / Couldn't convert Claims.");
        }
    }

    private String createRefreshToken() {
        return KeyGenerators.string().generateKey();
    }
}
