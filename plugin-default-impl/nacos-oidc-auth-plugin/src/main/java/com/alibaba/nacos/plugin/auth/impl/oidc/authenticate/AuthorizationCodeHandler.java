/*
 * Copyright 1999-2024 Alibaba Group Holding Ltd.
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

import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.oidc.config.OidcAuthConfig;
import com.alibaba.nacos.plugin.auth.impl.oidc.constant.OidcConstants;
import com.alibaba.nacos.plugin.auth.impl.oidc.identity.OidcUserMapper;
import com.alibaba.nacos.plugin.auth.impl.oidc.identity.OidcUserMapper.OidcUser;
import com.alibaba.nacos.plugin.auth.impl.oidc.token.JwtTokenValidator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Handles OIDC Authorization Code flow for user login.
 *
 * @author WangzJi
 */
public class AuthorizationCodeHandler {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationCodeHandler.class);
    
    private static volatile AuthorizationCodeHandler instance;
    
    private final OidcAuthConfig config;
    
    private final JwtTokenValidator tokenValidator;
    
    private final OidcUserMapper userMapper;
    
    private final SecureRandom secureRandom;
    
    private static final long STATE_EXPIRATION_MS = 10 * 60 * 1000L;
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    
    private AuthorizationCodeHandler() {
        this.config = OidcAuthConfig.getInstance();
        this.tokenValidator = JwtTokenValidator.getInstance();
        this.userMapper = OidcUserMapper.getInstance();
        this.secureRandom = new SecureRandom();
    }
    
    public static AuthorizationCodeHandler getInstance() {
        if (instance == null) {
            synchronized (AuthorizationCodeHandler.class) {
                if (instance == null) {
                    instance = new AuthorizationCodeHandler();
                }
            }
        }
        return instance;
    }
    
    public String buildAuthorizationUrl(String redirectUri) throws AccessException {
        try {
            String authEndpoint = config.getAuthorizationEndpoint();
            if (StringUtils.isBlank(authEndpoint)) {
                throw new AccessException("Authorization endpoint not configured");
            }
            
            String nonce = generateSecureToken();
            long expirationTime = System.currentTimeMillis() + STATE_EXPIRATION_MS;
            String state = buildSignedState(nonce, expirationTime);
            
            AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope(config.getScope().split(" ")),
                new ClientID(config.getClientId()),
                URI.create(redirectUri))
                .endpointURI(URI.create(authEndpoint))
                .state(new State(state))
                .nonce(new Nonce(nonce))
                .build();
            
            String authUrl = authRequest.toURI().toString();
            LOGGER.debug("Built authorization URL: {}", authUrl);
            return authUrl;
        } catch (AccessException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("Failed to build authorization URL", e);
            throw new AccessException("Failed to initiate login: " + e.getMessage());
        }
    }
    
    public OidcUser exchangeCodeForUser(String code, String state, String redirectUri)
        throws AccessException {
        try {
            StateData stateData = verifyAndDecodeState(state);
            if (stateData == null) {
                throw new AccessException("Invalid or expired state parameter");
            }
            
            OIDCTokens tokens = exchangeCodeForTokens(code, redirectUri);
            
            String idTokenString = tokens.getIDTokenString();
            if (StringUtils.isBlank(idTokenString)) {
                LOGGER.warn("OIDC token response does not contain id_token");
                throw new AccessException("ID token is required");
            }
            JWTClaimsSet claims = tokenValidator.validate(idTokenString);
            
            String tokenNonce = (String) claims.getClaim("nonce");
            if (tokenNonce == null) {
                String message = "Nonce not present in ID token";
                if (config.isStrictNonceValidation()) {
                    LOGGER.error("{} - Strict validation enabled, rejecting authentication",
                        message);
                    throw new AccessException(message
                        + ". Set 'nacos.core.auth.plugin.oidc.strict-nonce-validation=false' "
                        + "if your IdP doesn't support nonce.");
                } else {
                    LOGGER.warn("{} - Strict validation disabled, allowing authentication. "
                        + "This reduces protection against replay attacks.", message);
                }
            } else if (!stateData.nonce.equals(tokenNonce)) {
                String message = String.format("Nonce mismatch: expected %s, got %s",
                    stateData.nonce, tokenNonce);
                LOGGER.error("{} - Possible token replay attack detected", message);
                throw new AccessException(message);
            }
            
            OidcUser user = userMapper.mapToUser(claims);
            String accessToken = tokens.getAccessToken() == null
                ? null
                : tokens.getAccessToken().getValue();
            
            LOGGER.info(
                "OIDC token exchange succeeded for user={}, accessTokenFormat={}, accessTokenLength={}, "
                    + "idTokenFormat={}, idTokenLength={}, providerCompatibility={}",
                user.getUsername(), detectTokenFormat(accessToken), tokenLength(accessToken),
                detectTokenFormat(idTokenString), tokenLength(idTokenString),
                config.getProviderCompatibility());
            
            if (config.isAnyCrossCompatibilityEnabled()) {
                if (StringUtils.isNotBlank(config.getAuthorizationEvaluateEndpoint())) {
                    LOGGER.error("AnyCross OIDC compatibility cannot be used with external "
                        + "authorization endpoint");
                    throw new AccessException("AnyCross OIDC compatibility is incompatible with "
                        + "external authorization endpoint");
                }
                user.setToken(idTokenString);
                LOGGER.info("OIDC console session token selected for AnyCross: id_token, user={}",
                    user.getUsername());
            } else {
                if (StringUtils.isBlank(accessToken)) {
                    LOGGER.warn("OIDC token response does not contain access_token, user={}",
                        user.getUsername());
                    throw new AccessException("Access token is required");
                }
                user.setToken(accessToken);
                LOGGER.info("OIDC console session token selected: access_token, user={}",
                    user.getUsername());
            }
            
            LOGGER.info("User authenticated via authorization code: {}", user.getUsername());
            return user;
        } catch (AccessException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("Failed to exchange code for tokens", e);
            throw new AccessException("Authentication failed: " + e.getMessage());
        }
    }
    
    private OIDCTokens exchangeCodeForTokens(String code, String redirectUri) throws Exception {
        String tokenEndpoint = config.getTokenEndpoint();
        if (StringUtils.isBlank(tokenEndpoint)) {
            throw new AccessException("Token endpoint not configured");
        }
        
        AuthorizationCode authCode = new AuthorizationCode(code);
        AuthorizationGrant grant = new AuthorizationCodeGrant(authCode, URI.create(redirectUri));
        ClientAuthentication clientAuth = new ClientSecretBasic(
            new ClientID(config.getClientId()),
            new Secret(config.getClientSecret()));
        TokenRequest tokenRequest = new TokenRequest(
            URI.create(tokenEndpoint), clientAuth, grant);
        TokenResponse tokenResponse =
            OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
        
        if (!tokenResponse.indicatesSuccess()) {
            String error = tokenResponse.toErrorResponse().getErrorObject().getDescription();
            LOGGER.error("Token exchange failed: {}", error);
            throw new AccessException("Token exchange failed: " + error);
        }
        
        OIDCTokenResponse oidcResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
        return oidcResponse.getOIDCTokens();
    }
    
    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    private String buildSignedState(String nonce, long expirationTime) {
        String payload = nonce + "." + expirationTime;
        String signature = hmacSign(payload);
        String stateContent = payload + "." + signature;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            stateContent.getBytes(StandardCharsets.UTF_8));
    }
    
    private StateData verifyAndDecodeState(String state) {
        try {
            String decoded =
                new String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8);
            String[] parts = decoded.split("\\.");
            if (parts.length != 3) {
                LOGGER.warn("Invalid state format: expected 3 parts, got {}", parts.length);
                return null;
            }
            
            String nonce = parts[0];
            long expTime = Long.parseLong(parts[1]);
            String signature = parts[2];
            
            String payload = nonce + "." + expTime;
            if (!hmacVerify(payload, signature)) {
                LOGGER.warn("State signature verification failed");
                return null;
            }
            if (System.currentTimeMillis() > expTime) {
                LOGGER.warn("State has expired");
                return null;
            }
            return new StateData(nonce, expTime);
        } catch (NumberFormatException e) {
            LOGGER.warn("Invalid expiration time in state: {}", e.getMessage());
            return null;
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Invalid base64 encoding in state: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            LOGGER.warn("Failed to decode state: {}", e.getMessage());
            return null;
        }
    }
    
    private String hmacSign(String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(
                getSigningKey().getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
            mac.init(keySpec);
            byte[] signature = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign payload", e);
        }
    }
    
    private boolean hmacVerify(String payload, String signature) {
        String expectedSignature = hmacSign(payload);
        return expectedSignature.equals(signature);
    }
    
    private String getSigningKey() {
        String clientSecret = config.getClientSecret();
        if (StringUtils.isBlank(clientSecret)) {
            throw new IllegalStateException("Client secret is required for state signing");
        }
        return clientSecret;
    }
    
    private String detectTokenFormat(String token) {
        if (StringUtils.isBlank(token)) {
            return "missing";
        }
        int firstDot = token.indexOf('.');
        int secondDot = firstDot < 0 ? -1 : token.indexOf('.', firstDot + 1);
        int thirdDot = secondDot < 0 ? -1 : token.indexOf('.', secondDot + 1);
        return firstDot > 0 && secondDot > firstDot + 1 && thirdDot < 0
            ? "jwt-like"
            : "opaque";
    }
    
    private int tokenLength(String token) {
        return token == null ? 0 : token.length();
    }
    
    public String buildLogoutUrl(String idToken, String redirectUri) {
        String endSessionEndpoint = config.getEndSessionEndpoint();
        if (StringUtils.isBlank(endSessionEndpoint)) {
            return null;
        }
        
        StringBuilder logoutUrl = new StringBuilder(endSessionEndpoint);
        logoutUrl.append(OidcConstants.QUERY_STRING_SEPARATOR);
        if (StringUtils.isNotBlank(idToken)) {
            logoutUrl.append("id_token_hint=").append(idToken);
        }
        if (StringUtils.isNotBlank(redirectUri)) {
            char lastChar = logoutUrl.charAt(logoutUrl.length() - 1);
            if (lastChar != OidcConstants.QUERY_STRING_SEPARATOR.charAt(0)) {
                logoutUrl.append("&");
            }
            logoutUrl.append("post_logout_redirect_uri=").append(redirectUri);
        }
        logoutUrl.append("&client_id=").append(config.getClientId());
        return logoutUrl.toString();
    }
    
    private static class StateData {
        final String nonce;
        final long expirationTime;
        
        StateData(String nonce, long expirationTime) {
            this.nonce = nonce;
            this.expirationTime = expirationTime;
        }
    }
}
