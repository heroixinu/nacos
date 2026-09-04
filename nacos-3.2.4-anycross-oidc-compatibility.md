# Nacos 3.2.4 OIDC 兼容飞书 AnyCross opaque access_token 修改方案

> 目标版本：Nacos 3.2.4
> 目标场景：飞书 AnyCross 作为 OIDC Provider；`id_token` 为 JWT，可通过 JWKS 验证；`access_token` 为 opaque token，Nacos 3.2.4 后续 API 鉴权固定走 JWT/JWKS，导致 `Invalid token format`。

## 1. 结论

推荐采用一个**最小侵入、可配置、默认不改变官方行为**的兼容方案：

- 保留 Nacos 现有 Authorization Code 登录流程。
- 保留 `id_token` 的原有 JWKS 验证、nonce 校验、用户 claims 映射逻辑。
- 新增配置 `nacos.core.auth.plugin.oidc.console-token-source`：
  - `access_token`：官方默认行为。
  - `id_token`：AnyCross 兼容模式。
- 当配置为 `id_token` 时，登录回调成功后，Nacos 写给前端 `accessToken` Cookie 的内容改为已经验证过的 `id_token`。
- 后续浏览器继续按照 Nacos 原有方式提交 `Authorization: Bearer ...`；`OidcAuthenticationManager` 不需要改变认证逻辑，因为它本身就是 JWT/JWKS 校验，并且源码注释明确允许 “Access Token or ID Token”。
- 增加安全诊断日志，但**绝不输出原始 access_token、id_token、authorization code、client secret**。

该方案只需要修改 3 个核心 Java 文件；第 4 个文件的修改仅用于增强日志，可选但推荐。

---

## 2. 为什么这是当前最小方案

Nacos 3.2.4 当前链路为：

```text
AnyCross authorization endpoint
        |
        v
Nacos callback(code, state)
        |
        v
AnyCross token endpoint
        |
        +--> id_token     -- JWT
        |
        +--> access_token -- opaque
        |
        v
AuthorizationCodeHandler
        |
        +--> JwtTokenValidator.validate(id_token)   [成功]
        |
        +--> userMapper.mapToUser(id_token claims)
        |
        +--> user.setToken(access_token)            [问题点]
        |
        v
OidcLoginController
        |
        +--> Cookie("accessToken", user.getToken())
        |
        v
Nacos Web Console localStorage
        |
        v
Authorization: Bearer <opaque access_token>
        |
        v
OidcAuthenticationManager.authenticate()
        |
        +--> JwtTokenValidator.validate(opaque token)
        |
        v
Invalid token format
```

关键源码位置：

- `AuthorizationCodeHandler.exchangeCodeForUser()` 已经先验证 `id_token`。
- 同一个方法随后执行 `user.setToken(tokens.getAccessToken().getValue())`。
- `OidcLoginController.callback()` 把 `user.getToken()` 写到名为 `accessToken` 的 Cookie。
- `OidcAuthenticationManager.authenticate()` 无条件调用 `JwtTokenValidator.validate(token)`。

因此真正需要改变的只是“**Nacos Console 后续拿什么 JWT 当作自己的会话 Bearer token**”。

---

## 3. 适用前提

实施前确认以下条件：

1. AnyCross 返回的 `id_token` 是标准 JWT，并且 Nacos 当前能成功通过 JWKS 校验。
2. `id_token` 中包含 Nacos 当前用户映射所需 claims，例如 `sub`、用户名字段以及需要的角色字段。
3. 当前没有配置依赖 OAuth access token 的外部 `authorization-endpoint`。

### 3.1 非常重要：外部 authorization-endpoint

Nacos `OidcAuthenticationManager.hasPermission()` 会把：

```java
.token(user.getToken())
```

传给 `AuthorizationClient`。

开启本兼容模式后，`user.getToken()` 将是 `id_token`。

因此：

- **未配置外部 authorization endpoint：可直接使用本方案。**
- **配置了且外部服务强依赖 AnyCross access_token：不要直接使用本方案。** 此时应实现 UserInfo/introspection 或服务器侧 token session 映射。

---

# 4. 修改文件一：OidcConstants.java

文件：

```text
plugin-default-impl/nacos-oidc-auth-plugin/
src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/constant/OidcConstants.java
```

在配置常量区域增加：

```java
/**
 * Token delivered to Nacos console after OIDC login.
 * Supported values: access_token, id_token.
 */
public static final String CONFIG_CONSOLE_TOKEN_SOURCE =
    CONFIG_PREFIX + "console-token-source";
```

在 Default Values 区域增加：

```java
/**
 * Keep upstream behavior by default.
 */
public static final String DEFAULT_CONSOLE_TOKEN_SOURCE = "access_token";

public static final String CONSOLE_TOKEN_SOURCE_ACCESS_TOKEN = "access_token";

public static final String CONSOLE_TOKEN_SOURCE_ID_TOKEN = "id_token";
```

### 设计理由

默认必须保持 `access_token`，这样你的自定义构建仍然具备与官方 Nacos 3.2.4 相同的默认行为，不会因为以后更换 IdP 而自动进入 AnyCross 兼容路径。

---

# 5. 修改文件二：OidcAuthConfig.java

文件：

```text
plugin-default-impl/nacos-oidc-auth-plugin/
src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/config/OidcAuthConfig.java
```

## 5.1 增加成员变量

建议放在 `tokenValidationMethod` 附近：

```java
private String consoleTokenSource;
```

## 5.2 在 loadConfig() 中读取

在读取 `tokenValidationMethod` 后增加：

```java
this.consoleTokenSource = getProperty(
    OidcConstants.CONFIG_CONSOLE_TOKEN_SOURCE,
    OidcConstants.DEFAULT_CONSOLE_TOKEN_SOURCE);
```

## 5.3 增加配置校验

建议在 `loadConfig()` 中读取后立即规范化：

```java
if (!OidcConstants.CONSOLE_TOKEN_SOURCE_ACCESS_TOKEN.equalsIgnoreCase(consoleTokenSource)
    && !OidcConstants.CONSOLE_TOKEN_SOURCE_ID_TOKEN.equalsIgnoreCase(consoleTokenSource)) {
    LOGGER.warn("Unsupported OIDC console-token-source '{}', fallback to '{}'",
        consoleTokenSource, OidcConstants.DEFAULT_CONSOLE_TOKEN_SOURCE);
    this.consoleTokenSource = OidcConstants.DEFAULT_CONSOLE_TOKEN_SOURCE;
}
```

## 5.4 修改配置加载日志

原来：

```java
LOGGER.info("OIDC auth config loaded: issuerUri={}, clientId={}, tokenValidationMethod={}",
    issuerUri, clientId, tokenValidationMethod);
```

改为：

```java
LOGGER.info(
    "OIDC auth config loaded: issuerUri={}, clientId={}, tokenValidationMethod={}, consoleTokenSource={}",
    issuerUri, clientId, tokenValidationMethod, consoleTokenSource);
```

## 5.5 增加 getter

```java
public String getConsoleTokenSource() {
    return consoleTokenSource;
}

public boolean useIdTokenForConsole() {
    return OidcConstants.CONSOLE_TOKEN_SOURCE_ID_TOKEN.equalsIgnoreCase(consoleTokenSource);
}
```

不建议暴露 setter，除非现有测试风格需要。

---

# 6. 修改文件三：AuthorizationCodeHandler.java

文件：

```text
plugin-default-impl/nacos-oidc-auth-plugin/
src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/authenticate/AuthorizationCodeHandler.java
```

这是本次修改的核心。

Nacos 3.2.4 原始代码：

```java
// Validate ID token
String idTokenString = tokens.getIDTokenString();
JWTClaimsSet claims = tokenValidator.validate(idTokenString);

...

// Map claims to user
OidcUser user = userMapper.mapToUser(claims);
user.setToken(tokens.getAccessToken().getValue());

LOGGER.info("User authenticated via authorization code: {}", user.getUsername());
return user;
```

修改为：

```java
// Validate ID token
String idTokenString = tokens.getIDTokenString();
if (StringUtils.isBlank(idTokenString)) {
    LOGGER.warn("OIDC token response does not contain id_token");
    throw new AccessException("ID token is required");
}

JWTClaimsSet claims = tokenValidator.validate(idTokenString);

...

// Map claims to user
OidcUser user = userMapper.mapToUser(claims);

String accessToken = tokens.getAccessToken() == null
    ? null
    : tokens.getAccessToken().getValue();

LOGGER.info(
    "OIDC token exchange succeeded for user={}, accessTokenFormat={}, accessTokenLength={}, "
        + "idTokenFormat={}, idTokenLength={}, consoleTokenSource={}",
    user.getUsername(),
    detectTokenFormat(accessToken),
    tokenLength(accessToken),
    detectTokenFormat(idTokenString),
    tokenLength(idTokenString),
    config.getConsoleTokenSource());

if (config.useIdTokenForConsole()) {
    // AnyCross compatibility mode:
    // The AnyCross access_token may be opaque, while Nacos 3.2.4 validates
    // subsequent console bearer tokens exclusively as JWT/JWKS tokens.
    // id_token has already passed JWKS/claims/nonce validation above.
    user.setToken(idTokenString);
    LOGGER.info("OIDC console session token selected: id_token, user={}", user.getUsername());
} else {
    if (StringUtils.isBlank(accessToken)) {
        LOGGER.warn("OIDC token response does not contain access_token, user={}",
            user.getUsername());
        throw new AccessException("Access token is required");
    }
    user.setToken(accessToken);
    LOGGER.info("OIDC console session token selected: access_token, user={}", user.getUsername());
}

LOGGER.info("User authenticated via authorization code: {}", user.getUsername());
return user;
```

然后在类中增加两个安全辅助方法：

```java
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
```

### 为什么日志只打印 format 和 length

不要打印：

```java
LOGGER.info("accessToken={}", accessToken);
LOGGER.info("idToken={}", idTokenString);
LOGGER.info("code={}", code);
```

这些都属于凭证泄漏。

排障时只要看到：

```text
accessTokenFormat=opaque
idTokenFormat=jwt-like
consoleTokenSource=id_token
```

就已经足够证明兼容路径工作。

---

# 7. 修改文件四：OidcAuthenticationManager.java（推荐日志增强）

文件：

```text
plugin-default-impl/nacos-oidc-auth-plugin/
src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/authenticate/OidcAuthenticationManager.java
```

功能上不需要改这个类。

但为了上线后快速确认浏览器送回来的已经是 `id_token`，建议在 `authenticate(String token)` 内加入 DEBUG 日志。

原来：

```java
// Validate the token
JWTClaimsSet claims = tokenValidator.validate(token);
```

可以改为：

```java
LOGGER.debug("Validating OIDC bearer token: format={}, length={}",
    detectTokenFormat(token), token.length());

JWTClaimsSet claims = tokenValidator.validate(token);
```

并增加同样的：

```java
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
```

如果希望避免重复方法，也可以后续抽成 `TokenUtils`，但这次没有必要。为了控制 patch 面，重复十几行辅助代码反而更容易维护和回滚。

---

# 8. 不需要修改 OidcLoginController

`OidcLoginController.callback()` 当前执行：

```java
Cookie accessTokenCookie = new Cookie("accessToken", user.getToken());
```

虽然 Cookie 名仍叫 `accessToken`，但**建议不要改 Cookie 名**。

原因：

- Nacos 前端已经依赖这个名字。
- 它在这里实际承担的是“Nacos Console bearer credential”的角色。
- 修改 Cookie/localStorage 名会扩大到前端工程，完全没有必要。

因此 AnyCross 模式下的实际意义变成：

```text
Cookie name: accessToken
Cookie value: AnyCross id_token
```

这是刻意的兼容实现。

---

# 9. 配置

Nacos 3.2.4 当前源码使用的 OIDC 配置前缀为：

```text
nacos.core.auth.plugin.oidc.
```

因此新增：

```properties
nacos.core.auth.plugin.oidc.console-token-source=id_token
```

对于普通标准 IdP：

```properties
nacos.core.auth.plugin.oidc.console-token-source=access_token
```

默认即为 `access_token`，所以非 AnyCross 环境可以不配置。

如果你是 Docker 部署，最稳妥的方式是通过已有的 Nacos 配置注入机制或 JVM `-D` 参数把上述 property 传入，不建议在没有确认镜像环境变量映射规则前自行发明一个新的全大写环境变量名。

---

# 10. 为什么不推荐这次直接实现 UserInfo Token Validator

从 OIDC 语义来说，opaque access_token + `userinfo_endpoint` 更标准。

Nacos 3.2.4 的 `OidcAuthConfig` 甚至已经通过 Discovery 保存：

```java
private String userinfoEndpoint;
```

以及：

```java
public String getUserinfoEndpoint()
```

但这条方案作为本次修复并不划算：

1. 浏览器每一个 Nacos API 请求都需要验证 opaque token。
2. 如果每次请求 AnyCross UserInfo，会引入额外网络 RTT。
3. AnyCross 临时抖动会直接把 Nacos Console API 一起拖挂。
4. 必须设计本地 token cache、TTL、401 失效、并发刷新等逻辑。
5. Nacos 集群多实例时还需要决定缓存是实例级还是共享级。
6. UserInfo 返回 claims 是否包含 Nacos 所需角色字段还需要额外确认。

而 `id_token` 在 callback 阶段本来就已经被 Nacos：

- JWT parse
- JWKS signature verify
- issuer 校验
- audience 校验
- expiration 校验
- nonce 校验
- user mapping

因此对你当前“只解决 AnyCross opaque access_token 与 Nacos JWT-only validator 不兼容”的目标而言，直接复用它是改动最小的办法。

---

# 11. 构建

从 Nacos 3.2.4 tag 创建自己的分支：

```bash
git clone https://github.com/alibaba/nacos.git
cd nacos
git checkout 3.2.4
git switch -c custom/3.2.4-anycross-oidc
```

修改完成后，建议先只构建 OIDC 模块及其依赖：

```bash
./mvnw -pl plugin-default-impl/nacos-oidc-auth-plugin -am -DskipTests package
```

如果仓库没有可用的 Maven Wrapper，则：

```bash
mvn -pl plugin-default-impl/nacos-oidc-auth-plugin -am -DskipTests package
```

该模块 `pom.xml` 使用 `maven-shade-plugin`，会把 Nimbus OIDC/JWT 和 Caffeine 等运行时依赖打进 shaded/fat JAR，因此不要自己重新拆依赖。

构建成功后重点检查：

```bash
ls -lh plugin-default-impl/nacos-oidc-auth-plugin/target/
```

确认生成的 `nacos-oidc-auth-plugin-3.2.4*.jar`。

---

# 12. 替换方式

这里不要盲目假设你当前镜像里的 JAR 路径。

先在运行中的 Nacos 容器里找出实际插件 JAR：

```bash
docker exec -it <nacos-container> sh
find /home/nacos -name '*oidc*auth*plugin*.jar' -o -name 'nacos-oidc-auth-plugin*.jar'
```

如果 `/home/nacos` 找不到，再扩大：

```bash
find / -name 'nacos-oidc-auth-plugin*.jar' 2>/dev/null
```

记录原始路径，然后退出容器。

## 强烈建议：不要直接在运行容器里永久覆盖

生产环境建议做一个派生镜像：

```dockerfile
FROM nacos/nacos-server:v3.2.4

COPY nacos-oidc-auth-plugin-3.2.4.jar \
  /实际查到的原始jar路径/nacos-oidc-auth-plugin-3.2.4.jar
```

如果实际文件名不同，以容器中查到的文件为准。

然后：

```bash
docker build -t your-registry/nacos:3.2.4-anycross-oidc .
docker compose up -d --force-recreate nacos
```

不要把 `docker cp` 作为长期部署方式，因为下一次 recreate/update 就会丢失修改。

---

# 13. 上线前验证

## 13.1 验证配置加载

启动日志应出现类似：

```text
OIDC auth config loaded: issuerUri=..., clientId=..., tokenValidationMethod=jwt, consoleTokenSource=id_token
```

如果显示：

```text
consoleTokenSource=access_token
```

说明新配置没有成功注入。

## 13.2 执行一次 SSO 登录

期望日志：

```text
OIDC token exchange succeeded for user=xxx,
accessTokenFormat=opaque,
accessTokenLength=...,
idTokenFormat=jwt-like,
idTokenLength=...,
consoleTokenSource=id_token
```

随后：

```text
OIDC console session token selected: id_token, user=xxx
User authenticated via authorization code: xxx
```

## 13.3 后续 API 请求

如果打开 DEBUG 日志，期望：

```text
Validating OIDC bearer token: format=jwt-like, length=...
```

而不再出现：

```text
Invalid token format
```

## 13.4 浏览器 Network 验证

登录 Nacos 后打开 DevTools -> Network，选择一个 `/v1/`、`/v2/` 或 `/v3/` API 请求。

检查：

```text
Authorization: Bearer xxxxx.yyyyy.zzzzz
```

只确认其存在三个 JWT 段即可。

**不要把完整 token 截图、复制到工单或聊天中。**

---

# 14. 必测功能

至少验证：

- SSO 登录。
- 首页正常加载。
- Namespace 列表。
- Configuration 列表。
- Service Management 列表。
- 当前用户管理员权限。
- 页面刷新后仍能访问 API。
- token 过期后的行为。
- 退出登录后重新登录。
- Nacos 容器重启后重新登录。

如果你使用多个 Nacos Server 实例，再验证经过不同实例请求时均可成功。这个方案本身无服务器 session，因此天然适合多实例。

---

# 15. token 生命周期注意事项

改成 `id_token` 后，Nacos Console 的有效登录周期实际上受 `id_token.exp` 控制。

如果 AnyCross：

```text
access_token = 2h
id_token     = 1h
```

则 Nacos Console 实际约 1 小时后就需要重新认证。

这是预期行为，不要人为跳过 JWT `exp` 校验。

如果有效期太短，应调整 AnyCross 的 ID Token 生命周期；不要在 Nacos 中关闭 expiration 校验。

---

# 16. 安全注意事项

本方案属于针对 Nacos 3.2.4 实现约束的兼容 patch，而不是通用 OIDC 最佳实践。

需要明确：

1. 标准 OIDC 中，ID Token 主要用于 Client 身份认证语义；Access Token 用于访问 Resource Server。
2. 本方案把已经验证的 ID Token 作为 **Nacos 自己的 Console session bearer credential**。
3. 不把 ID Token 拿去访问飞书/AnyCross API。
4. 不关闭 signature、issuer、audience、expiration、nonce 校验。
5. 不记录任何原始 token。
6. ID Token 通常包含比 opaque access token 更多的用户 claims；现在它会进入浏览器 localStorage，因此需要接受这一暴露面变化。
7. Nacos Console 本来就将 bearer token 放入前端可读取 Cookie/localStorage，所以这里并没有改变 Nacos 前端 token 存储模型，但 ID Token 本身可能包含更多可读信息。

---

# 17. 回滚

代码无需重新构建即可逻辑回滚到官方 token 行为：

```properties
nacos.core.auth.plugin.oidc.console-token-source=access_token
```

然后重启 Nacos。

但 AnyCross opaque access_token 场景下，回滚后会重新出现：

```text
Invalid token format
```

完整二进制回滚则重新使用官方 Nacos 3.2.4 镜像/JAR。

---

# 18. 推荐 Git Commit

```text
fix(oidc): support id_token as console bearer token for opaque access-token providers
```

commit message 可写：

```text
Nacos 3.2.4 validates console bearer tokens exclusively through JWT/JWKS.
Some OIDC providers such as AnyCross return opaque OAuth access tokens while
issuing JWT ID tokens.

Add a backward-compatible console-token-source option. The default remains
access_token. When id_token is selected, the already validated OIDC ID token
is delivered to the Nacos console and reused by the existing JWT validation
pipeline.

Raw tokens are never logged; diagnostic logs expose only token format and
length.
```

---

# 19. 最终建议

对于当前 AnyCross + Nacos 3.2.4 场景，推荐直接采用：

```properties
nacos.core.auth.plugin.oidc.console-token-source=id_token
```

以及上述 3 个核心文件修改。

**不要在第一版实现 UserInfo/introspection。**

原因不是它不标准，而是它会把一个非常局部的兼容问题扩大成“远程 token validator + cache + IdP 可用性依赖”的新子系统。

如果未来 Nacos 官方真正实现 RFC 7662 introspection，或者 AnyCross 提供稳定 introspection endpoint，再迁移回标准 opaque access-token validation 即可。

---

# 20. 本方案依据的 Nacos 3.2.4 源码

- `plugin-default-impl/nacos-oidc-auth-plugin/src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/authenticate/AuthorizationCodeHandler.java`
- `plugin-default-impl/nacos-oidc-auth-plugin/src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/authenticate/OidcAuthenticationManager.java`
- `plugin-default-impl/nacos-oidc-auth-plugin/src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/config/OidcAuthConfig.java`
- `plugin-default-impl/nacos-oidc-auth-plugin/src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/constant/OidcConstants.java`
- `plugin-default-impl/nacos-oidc-auth-plugin/src/main/java/com/alibaba/nacos/plugin/auth/impl/oidc/controller/OidcLoginController.java`
- `plugin-default-impl/nacos-oidc-auth-plugin/pom.xml`

源码 tag：`3.2.4`。
