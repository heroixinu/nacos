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

package com.alibaba.nacos.plugin.auth.impl.oidc.config;

import com.alibaba.nacos.plugin.auth.impl.oidc.constant.OidcConstants;
import com.alibaba.nacos.sys.env.EnvUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcAuthConfigProviderCompatibilityTest {
    
    private ConfigurableEnvironment originalEnvironment;
    
    @BeforeEach
    void setUp() {
        originalEnvironment = EnvUtil.getEnvironment();
        EnvUtil.setEnvironment(new MockEnvironment());
        ReflectionTestUtils.setField(OidcAuthConfig.class, "instance", null);
    }
    
    @AfterEach
    void tearDown() {
        EnvUtil.setEnvironment(originalEnvironment);
        ReflectionTestUtils.setField(OidcAuthConfig.class, "instance", null);
    }
    
    @Test
    void testStandardCompatibilityIsDefault() {
        OidcAuthConfig config = OidcAuthConfig.getInstance();
        assertEquals(OidcConstants.PROVIDER_COMPATIBILITY_STANDARD,
            config.getProviderCompatibility());
        assertFalse(config.isAnyCrossCompatibilityEnabled());
    }
    
    @Test
    void testAnyCrossCompatibilityCanBeEnabledExplicitly() {
        EnvUtil.setEnvironment(new MockEnvironment().withProperty(
            OidcConstants.CONFIG_PROVIDER_COMPATIBILITY,
            OidcConstants.PROVIDER_COMPATIBILITY_ANYCROSS));
        ReflectionTestUtils.setField(OidcAuthConfig.class, "instance", null);
        
        OidcAuthConfig config = OidcAuthConfig.getInstance();
        
        assertEquals(OidcConstants.PROVIDER_COMPATIBILITY_ANYCROSS,
            config.getProviderCompatibility());
        assertTrue(config.isAnyCrossCompatibilityEnabled());
    }
    
    @Test
    void testUnknownCompatibilityFallsBackToStandard() {
        EnvUtil.setEnvironment(new MockEnvironment().withProperty(
            OidcConstants.CONFIG_PROVIDER_COMPATIBILITY, "unknown-provider"));
        ReflectionTestUtils.setField(OidcAuthConfig.class, "instance", null);
        
        OidcAuthConfig config = OidcAuthConfig.getInstance();
        
        assertEquals(OidcConstants.PROVIDER_COMPATIBILITY_STANDARD,
            config.getProviderCompatibility());
        assertFalse(config.isAnyCrossCompatibilityEnabled());
    }
}
