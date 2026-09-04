/*
 * Copyright 1999-2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.auth.impl.oidc.authenticate;

import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.oidc.config.OidcAuthConfig;
import com.alibaba.nacos.plugin.auth.impl.oidc.constant.OidcConstants;
import com.alibaba.nacos.plugin.auth.impl.oidc.identity.OidcUserMapper;
import com.alibaba.nacos.plugin.auth.impl.oidc.identity.OidcUserMapper.OidcUser;
import com.alibaba.nacos.plugin.auth.impl.oidc.token.JwtTokenValidator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class AuthorizationCodeHandlerAnyCrossCompatibilityTest {
    
    @AfterEach
    void tearDown() {
        ReflectionTestUtils.setField(AuthorizationCodeHandler.class, "instance", null);
    }
    
    @Test
    void testAnyCrossUsesValidatedIdTokenForConsole() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("subject")
            .claim("nonce", "nonce")
            .build();
        String idToken = new PlainJWT(claims).serialize();
        HttpServer server = startTokenServer(idToken);
        try {
            OidcAuthConfig config = tokenConfig(server);
            when(config.isAnyCrossCompatibilityEnabled()).thenReturn(true);
            when(config.getProviderCompatibility()).thenReturn(
                OidcConstants.PROVIDER_COMPATIBILITY_ANYCROSS);
            
            OidcUser result = exchange(config, claims, idToken);
            
            assertEquals(idToken, result.getToken());
        } finally {
            server.stop(0);
        }
    }
    
    @Test
    void testAnyCrossRejectsExternalAuthorizationEndpoint() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("subject")
            .claim("nonce", "nonce")
            .build();
        String idToken = new PlainJWT(claims).serialize();
        HttpServer server = startTokenServer(idToken);
        try {
            OidcAuthConfig config = tokenConfig(server);
            when(config.isAnyCrossCompatibilityEnabled()).thenReturn(true);
            when(config.getProviderCompatibility()).thenReturn(
                OidcConstants.PROVIDER_COMPATIBILITY_ANYCROSS);
            when(config.getAuthorizationEvaluateEndpoint()).thenReturn("http://idp/evaluate");
            
            assertThrows(AccessException.class, () -> exchange(config, claims, idToken));
        } finally {
            server.stop(0);
        }
    }
    
    private OidcUser exchange(OidcAuthConfig config, JWTClaimsSet claims, String idToken)
        throws Exception {
        JwtTokenValidator validator = mock(JwtTokenValidator.class);
        when(validator.validate(idToken)).thenReturn(claims);
        OidcUserMapper mapper = mock(OidcUserMapper.class);
        OidcUser user = new OidcUser();
        user.setUsername("nacos");
        when(mapper.mapToUser(claims)).thenReturn(user);
        AuthorizationCodeHandler handler = newHandler(config, validator, mapper);
        String state = ReflectionTestUtils.invokeMethod(handler, "buildSignedState", "nonce",
            System.currentTimeMillis() + 60_000L);
        return handler.exchangeCodeForUser("code", state, "http://nacos/callback");
    }
    
    private OidcAuthConfig tokenConfig(HttpServer server) {
        OidcAuthConfig config = mock(OidcAuthConfig.class);
        when(config.getTokenEndpoint()).thenReturn(
            "http://127.0.0.1:" + server.getAddress().getPort() + "/token");
        when(config.getClientId()).thenReturn("client");
        when(config.getClientSecret()).thenReturn("secret");
        when(config.isStrictNonceValidation()).thenReturn(true);
        return config;
    }
    
    private AuthorizationCodeHandler newHandler(OidcAuthConfig config,
        JwtTokenValidator validator, OidcUserMapper mapper) {
        ReflectionTestUtils.setField(AuthorizationCodeHandler.class, "instance", null);
        try (MockedStatic<OidcAuthConfig> configStatic = mockStatic(OidcAuthConfig.class);
            MockedStatic<JwtTokenValidator> validatorStatic = mockStatic(JwtTokenValidator.class);
            MockedStatic<OidcUserMapper> mapperStatic = mockStatic(OidcUserMapper.class)) {
            configStatic.when(OidcAuthConfig::getInstance).thenReturn(config);
            validatorStatic.when(JwtTokenValidator::getInstance).thenReturn(validator);
            mapperStatic.when(OidcUserMapper::getInstance).thenReturn(mapper);
            return AuthorizationCodeHandler.getInstance();
        }
    }
    
    private HttpServer startTokenServer(String idToken) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", exchange -> {
            String body = "{\"access_token\":\"opaque-access-token\","
                + "\"token_type\":\"Bearer\",\"id_token\":\"" + idToken + "\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return server;
    }
}
