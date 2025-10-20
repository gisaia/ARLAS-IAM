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

package io.arlas.iam.test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.path.json.JsonPath;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.junit.Test;

import java.security.interfaces.RSAPublicKey;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class JwksTokenValidationTest extends AuthEndpoints {

    @Test
    public void validateTokenWithJwks() throws Exception {
        ExtractableResponse<Response> response = login(ADMIN,ADMIN_PASSWORD).then().statusCode(200).extract();

        JsonPath json = response.jsonPath();
        String token = json.get("access_token");

        Response jwksResp = given()
                .contentType("application/json")
                .get(arlasAppPath.concat(".well-known/jwks.json")).then().statusCode(200).extract().response();

        String jwksJson = jwksResp.getBody().asString();
        JWKSet jwkSet = JWKSet.parse(jwksJson);

        SignedJWT signedJWT = SignedJWT.parse(token);

        JWK jwk = jwkSet.getKeys().get(0);
        assertTrue("expected RSA JWK",jwk instanceof RSAKey);

        RSAKey rsaJwk = (RSAKey) jwk;
        RSAPublicKey publicKey = rsaJwk.toRSAPublicKey();

        boolean valid = signedJWT.verify(new RSASSAVerifier(publicKey));
        assertTrue("JWT signature must be valid using JWKS key", valid);
    }
}
