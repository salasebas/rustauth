# Plan checklist upstream: paquete principal `better-auth`

Esta es una guia de planeacion reutilizable, no una auditoria de avance del proyecto actual. Cada checklist se marca como completado cuando OpenAuth implemente el comportamiento servidor equivalente de forma idiomatica en Rust; si se agrega un comportamiento mejor, mas seguro o mas completo que cubre la intencion upstream, tambien se marca como completado aunque la estructura no sea 1:1.

Origen analizado: `upstream/better-auth/1.6.9/repository/packages/better-auth`.

Alcance: comportamiento de servidor necesario para usar la libreria principal de Better Auth/OpenAuth: inicializacion, runtime HTTP, contexto, endpoints, cookies, crypto, DB, OAuth/social, plugins, adapters, migraciones, test-utils servidor y contratos publicos. Se excluye browser-only/TypeScript-only como SDKs de cliente y bindings de frameworks, salvo como referencia de superficie HTTP esperada.

Avance marcado el 2026-05-12: `[x]` significa que el comportamiento existe en OpenAuth y tiene cobertura de pruebas en `crates/openauth/tests` o `crates/openauth-core/tests`. Los puntos parcialmente implementados o sin prueba directa permanecen sin marcar.

## Recomendacion de arquitectura

- [x] Mantener `crates/openauth` como fachada publica y punto ergonomico de instalacion.
- [x] Evitar que `crates/openauth` concentre la logica pesada de runtime, plugins, DB, cookies, crypto o providers.
- [ ] Usar `crates/openauth` para re-exportar tipos, builders, errores, helpers estables y presets feature-gated.
- [ ] Permitir que `crates/openauth` tenga glue minimo: constructor `OpenAuth`/builder, defaults de feature flags, y re-exports documentados.
- [ ] Mover inicializacion de servidor, contexto, endpoints base, cookies, sesiones, adapters internos, hooks, rate limit y validacion a `crates/openauth-core`.
- [ ] Mover OAuth/OIDC cliente, providers sociales, PKCE, refresh token y linking provider-agnostic a `crates/openauth-oauth` o a modulos core + oauth segun dependencia.
- [ ] Mantener en `openauth-core` solo contratos provider-agnostic: usuario, cuenta, sesion, verification, state storage, session creation y account linking.
- [ ] Implementar providers oficiales como tipos/modulos feature-gated, no como dependencias obligatorias del core.
- [ ] Ubicar OIDC Provider, MCP, SIWE y otros plugins grandes en crates o features separadas si crecen demasiado.
- [ ] Re-exportar plugins desde `crates/openauth` solo como API publica conveniente.
- [ ] Evitar ciclos: el core no debe depender de la fachada; la fachada depende de core y crates feature-gated.
- [ ] Documentar que el paquete principal Rust es la entrada publica, pero no el duenio de la implementacion.

## Superficie publica de la libreria principal

- [x] Export principal equivalente a `betterAuth` como constructor servidor.
- [ ] Export minimo equivalente a `minimal` para inicializacion sin stack de migraciones/adapters pesados.
- [ ] Re-export de `core`, `context`, `db`, `oauth2`, `utils`, `error`, `env` y tipos publicos.
- [x] Re-export de `APIError`/errores tipados equivalentes.
- [x] Re-export de cookies servidor.
- [x] Re-export de crypto servidor seguro.
- [x] Re-export de adapters/factories como contrato, no implementacion acoplada.
- [ ] Re-export de social providers via feature `oauth`/`social-providers`.
- [ ] Re-export de plugins servidor via features.
- [ ] Re-export de telemetry solo si feature `telemetry` esta habilitada.
- [ ] Mantener compatibilidad de nombres publicos utiles sin copiar el shape TypeScript innecesario.
- [ ] Definir claramente que `client`, React, Vue, Svelte, Solid, Lynx, Next, TanStack y browser fetch managers quedan fuera del core Rust.

## Dependencias upstream y equivalentes funcionales

- [ ] `@better-auth/core`: contratos base, errores, context async, DB schema, instrumentation, social providers.
- [ ] `better-call`: router, endpoints, middleware, response conversion, cookies/headers.
- [ ] `jose`: JWT/JWE/JWK, OIDC, JWKS, firma/verificacion.
- [x] `@noble/ciphers` y `@noble/hashes`: XChaCha20-Poly1305, HKDF, SHA-256.
- [ ] `@better-auth/utils`: base64url, binary, HMAC, password hashing, random, webcrypto.
- [ ] `zod`: validacion de inputs y schemas; en Rust usar validadores tipados/serde + errores explicitos.
- [ ] `defu`: merge profundo de opciones/plugin init; en Rust usar builder/defaults explicitos.
- [ ] `@better-fetch/fetch`: cliente HTTP usado por tests/social; en Rust usar HTTP client abstraido para servidor.
- [ ] `kysely`: migraciones/introspeccion SQL upstream; en Rust planear generacion/migraciones por adapter.
- [ ] Adapters upstream (`drizzle`, `kysely`, `memory`, `mongo`, `prisma`) como referencia de contratos, no dependencias Rust directas.
- [ ] `nanostores` y framework deps son client-only; excluir de runtime servidor.

## Inicializacion auth

- [ ] Implementar constructor full con DB/adapters/migraciones disponibles.
- [ ] Implementar constructor minimal sin migraciones automaticas.
- [x] Exponer `handler(request)` servidor.
- [ ] Exponer API directa equivalente a `auth.api.*`.
- [ ] Exponer opciones normalizadas.
- [ ] Exponer contexto inicializable de forma lazy/async.
- [ ] Exponer codigos de error base + codigos de plugins.
- [ ] Resolver `baseURL` estatico desde opciones/env/request.
- [ ] Resolver `baseURL` dinamico por request con `allowedHosts`, protocolo y fallback.
- [ ] Rehidratar trusted origins y providers por request cuando `baseURL` es dinamico.
- [ ] Evitar usar base URL vacio en llamadas directas; devolver error claro.
- [ ] Ejecutar handler bajo contexto de adapter actual.
- [ ] Fusionar error codes de plugins antes o junto a los codigos base.
- [ ] Incluir pruebas de full init, minimal init, trusted origins y handler/direct API.

## Contexto servidor

- [ ] Crear `AuthContext` con adapter, opciones, tablas, cookies, providers, logger, secrets y runtime helpers.
- [ ] Soportar modo stateless cuando no hay DB: cookie cache JWE, state en cookie y account cookie.
- [ ] Validar `baseURL` dinamico con `allowedHosts` no vacio.
- [x] Inferir `basePath` por defecto `/api/auth`.
- [ ] Normalizar origen/base path sin doble slash ni protocolos invalidos.
- [ ] Leer `BETTER_AUTH_URL`, `NEXT_PUBLIC_BETTER_AUTH_URL`, `PUBLIC_BETTER_AUTH_URL`, `NUXT_PUBLIC_*`, `BASE_URL`.
- [ ] Leer `BETTER_AUTH_TRUSTED_ORIGINS`.
- [x] Leer secrets desde opciones, `BETTER_AUTH_SECRETS`, `BETTER_AUTH_SECRET`, `AUTH_SECRET`.
- [x] Bloquear secret default en produccion.
- [ ] Advertir secret corto o baja entropia.
- [x] Soportar secret rotation con version actual, keys y legacy secret.
- [ ] Inicializar providers sociales sync/async, omitir disabled/null y advertir credenciales faltantes.
- [ ] Aplicar `disableImplicitSignUp` global/provider.
- [ ] Inicializar telemetry con adapter/database.
- [ ] Registrar plugins internos.
- [ ] Implementar `getPlugin`, `hasPlugin`, set de plugin IDs.
- [ ] Construir trusted providers desde config estatica/dinamica.
- [x] Implementar `isTrustedOrigin` con wildcards, host-only patterns y relative paths controlados.
- [x] Configurar sesiones: `updateAge`, `expiresIn`, `freshAge`, `cookieRefreshCache`.
- [ ] Desactivar o advertir cache de cookie si DB/secondary storage lo vuelve inseguro o inconsistente.
- [ ] Configurar rate limit por entorno, storage y custom rules.
- [x] Configurar password hash/verify/check.
- [ ] Mantener `setNewSession`, `newSession` y estado de sesion por request.
- [x] Proveer `createAuthCookie` y cookies derivadas de opciones.
- [ ] Ejecutar `runPluginInit` con merge de opciones, trusted origins, contexto extendido y DB hooks.
- [ ] Agregar DB hooks globales despues de hooks de plugins.
- [ ] Re-crear internal adapter despues de plugin init.
- [ ] Pruebas de create-context, init, init-minimal y dynamic baseURL.

## Runtime de endpoints y router

- [ ] Fusionar endpoints base, endpoints de plugins, `ok` y `error`.
- [ ] Detectar conflictos de endpoint path + method entre plugins.
- [ ] Convertir endpoints a API directa con wrapper equivalente a `toAuthEndpoints`.
- [x] Preservar `path`, `method`, `operationId` y metadata OpenAPI por endpoint.
- [x] En endpoints, usar constructor central equivalente a `createAuthEndpoint` o wrapper Rust tipado.
- [ ] Resolver contexto dinamico para llamadas directas con `headers`/`request`/fallback.
- [ ] Ejecutar before hooks user y plugin con matchers.
- [ ] Permitir que before hooks muten contexto/headers o devuelvan response.
- [ ] Ejecutar handler con contexto endpoint/request state.
- [ ] Ejecutar after hooks user y plugin.
- [ ] Preservar headers y `set-cookie` cuando un handler lanza APIError.
- [ ] Re-lanzar APIError en API directa cuando no se pide Response.
- [ ] Convertir resultado a Response cuando se llama via HTTP handler.
- [ ] Mantener status y headers en respuesta directa opcional.
- [ ] Instrumentar spans por endpoint, handler y hooks con route/operationId/context.
- [x] Soportar `onRequest` de plugins que puede devolver response o mutar request.
- [x] Soportar `onResponse` de plugins que puede reemplazar response.
- [x] Respetar disabled paths con 404.
- [x] Configurar media types JSON permitidos.
- [x] Respetar `skipTrailingSlashes`.
- [ ] Manejar `onAPIError.throw`, `onAPIError.onError`, `errorURL` y redirects 302.
- [ ] Pruebas de endpoint conflicts, router, `toAuthEndpoints`, `call`, instrumentation endpoint.

## Middleware y seguridad HTTP

- [x] Origin check para mutaciones: omitir GET/OPTIONS/HEAD.
- [ ] Validar `origin`/`referer` contra trusted origins cuando hay cookies o validacion forzada.
- [x] Rechazar origin faltante/null cuando aplica.
- [ ] Validar `callbackURL`, `redirectTo`, `errorCallbackURL`, `newUserCallbackURL`.
- [ ] Permitir relative paths solo donde aplica y bloquear `//`, backslash, `%2f`, `%5c`.
- [ ] Soportar `disableOriginCheck`, path allowlist y compatibilidad temporal con CSRF.
- [x] Soportar `disableCSRFCheck` separado.
- [ ] Loggear advertencia de deprecacion si `disableOriginCheck` tambien deshabilita CSRF.
- [ ] Implementar `requireResourceOwnership`.
- [ ] Implementar `requireOrgRole` dependiente del plugin organization.
- [ ] Pruebas de authorization middleware y origin-check.

## Rate limiting

- [ ] Rate limit habilitado por defecto en produccion.
- [ ] Storage memory con TTL.
- [ ] Storage secondary-storage con TTL.
- [ ] Storage database sobre tabla `rateLimit`.
- [ ] Storage custom.
- [x] Key por IP normalizada + path.
- [x] Resolver IP desde headers configurados, `x-forwarded-for` por defecto.
- [ ] Soportar opt-out de IP tracking.
- [x] Fallback localhost en dev/test.
- [ ] Advertir una vez si no se puede determinar IP.
- [ ] Reglas especiales: sign-in/sign-up/change-password/change-email con 3/10s.
- [ ] Reglas especiales: password reset, email verification y email-otp con 3/60s.
- [ ] Reglas de plugins.
- [x] Reglas custom con wildcard y funcion dinamica.
- [x] Responder 429 con `X-Retry-After`.
- [x] Actualizar contador en response, no solo request.
- [x] Pruebas de rate limiter.

## Endpoints base

- [x] `ok` GET `/ok`.
- [ ] `error` GET `/error`.
- [ ] `signInSocial` POST `/sign-in/social` con OpenAPI `socialSignIn`.
- [ ] `callbackOAuth` GET/POST `/callback/:id` con OpenAPI `handleOAuthCallback`.
- [x] `signInEmail` POST `/sign-in/email` con OpenAPI `signInEmail`.
- [x] `signUpEmail` POST `/sign-up/email` con OpenAPI `signUpWithEmailAndPassword`.
- [x] `signOut` POST `/sign-out` con OpenAPI `signOut`.
- [x] `getSession` GET/POST `/get-session` con OpenAPI `getSession`.
- [x] `listSessions` GET `/list-sessions` con OpenAPI `listUserSessions`.
- [x] `revokeSession` POST `/revoke-session`.
- [x] `revokeSessions` POST `/revoke-sessions`.
- [x] `revokeOtherSessions` POST `/revoke-other-sessions`.
- [ ] `updateSession` POST `/update-session`.
- [x] `requestPasswordReset` POST `/request-password-reset`.
- [ ] `requestPasswordResetCallback` GET password reset callback.
- [x] `resetPassword` POST `/reset-password`.
- [x] `verifyPassword` POST `/verify-password`.
- [x] `sendVerificationEmail` POST `/send-verification-email`.
- [x] `verifyEmail` GET `/verify-email`.
- [x] `updateUser` POST `/update-user`.
- [x] `changePassword` POST `/change-password`.
- [x] `setPassword` POST `/set-password`.
- [x] `deleteUser` POST `/delete-user`.
- [x] `deleteUserCallback` GET delete callback.
- [x] `changeEmail` POST `/change-email`.
- [x] `listUserAccounts` GET `/list-accounts`.
- [ ] `linkSocialAccount` POST `/link-social`.
- [x] `unlinkAccount` POST `/unlink-account`.
- [ ] `getAccessToken` POST `/get-access-token`.
- [ ] `refreshToken` POST `/refresh-token`.
- [ ] `accountInfo` GET `/account-info`.
- [ ] Mantener schemas de input/output y errores por endpoint.
- [ ] Mantener middlewares `session`, `sensitiveSession`, `requestOnlySession`, `freshSession`.
- [ ] Pruebas por ruta: account, email verification, password, session API, sign-in, sign-out, sign-up, update-user, error.

## Cookies de servidor

- [x] Crear cookies desde prefix configurable, default `better-auth`.
- [ ] Soportar nombres/atributos por cookie en `advanced.cookies`.
- [x] Aplicar `__Secure-` cuando corresponde.
- [ ] Calcular secure por `useSecureCookies`, protocolo dynamic/static o produccion.
- [x] `sameSite=lax`, `path=/`, `httpOnly=true` por defecto.
- [x] Soportar defaultCookieAttributes.
- [x] Soportar cross-subdomain cookies con domain explicito o baseURL.
- [x] Fallar si cross-subdomain requiere domain/baseURL y no hay dynamic config valida.
- [x] Cookies base: `session_token`, `session_data`, `account_data`, `dont_remember`.
- [x] Firmar session token.
- [ ] Soportar `dontRememberMe` con cookie de sesion sin maxAge y expiracion logica de 1 dia.
- [x] Setear cookie cache de sesion si esta habilitada.
- [ ] Filtrar campos de session/user antes de cookie cache.
- [ ] Versionar cookie cache con string o funcion.
- [x] Estrategias cookie cache: compact base64url+HMAC, JWT HS256, JWE A256CBC-HS512.
- [x] Validar firma/expiracion/version al leer cookie cache.
- [x] Soportar chunking automatico sobre 4096 bytes con limpieza de chunks previos.
- [x] Reconstruir cookies chunked por indice.
- [ ] Borrar session token, session data, account data, oauth state y dontRemember.
- [ ] Soportar account cookie cifrada con JWE y chunking.
- [x] Parsear `Set-Cookie` combinado en multiples cookies.
- [ ] Convertir Set-Cookie a header Cookie para flujos internos/tests.
- [ ] Leer session cookie con y sin `__Secure-`, y compat legacy `better-auth-session_token`.
- [x] Pruebas de cookies, chunking, cache y parse headers.

## Crypto servidor

- [x] `symmetricEncrypt`/`symmetricDecrypt` con XChaCha20-Poly1305 y nonce gestionado.
- [x] Derivar key con SHA-256 del secret.
- [x] Envelope `$ba$<version>$<ciphertext>` para secret rotation.
- [x] Decrypt de payload legacy bare-hex con legacy secret.
- [x] Errores claros si version secret no existe.
- [x] HMAC SHA-256 para signed cookies/signature.
- [x] `signJWT` HS256 con iat/exp.
- [x] `verifyJWT` que devuelve null en fallo.
- [x] JWE simetrico con `dir` + `A256CBC-HS512`.
- [x] Derivar secret de JWE con HKDF SHA-256 y salt especifico.
- [x] Incluir `kid` como thumbprint de key derivada.
- [x] Decode JWE con secret actual, secrets versionados y fallback sin kid.
- [x] Tolerancia de reloj de 15s para JWT decrypt.
- [ ] Password hashing/verify con algoritmo seguro no bloqueante equivalente a scrypt/Argon2.
- [x] Random string generator con alfabeto `a-z`, `A-Z`, `0-9`, `-_`.
- [x] Pruebas de password, secret rotation, JWT/JWE y token encryption.

## DB, schemas y adapters internos

- [x] Contrato DB adapter con CRUD, count, transactions, joins, sort, limit/offset.
- [ ] Fallback memory adapter si no hay DB.
- [ ] Adapter por funcion configurable.
- [ ] Adapter directo full equivalente a Kysely cuando aplica.
- [ ] Parche/compat para adapter sin transaction con advertencia.
- [ ] Internal adapter sobre adapter publico.
- [ ] DB hooks para create/update/updateMany/delete/deleteMany.
- [ ] Hooks before pueden cancelar con `false`.
- [ ] Hooks before pueden mutar data.
- [ ] Hooks after se encolan post-transaction.
- [ ] Instrumentar hooks DB con modelo/tipo/contexto.
- [ ] `createOAuthUser` transaccional user + account.
- [x] `createUser` normaliza email lowercase.
- [x] `createAccount`.
- [ ] `listUsers`, `countTotalUsers`.
- [ ] `deleteUser` borra sessions/accounts/user respetando secondary storage.
- [ ] `createSession` con ip, user-agent, token random, expiracion y additional fields default.
- [ ] Soportar session en secondaryStorage sin DB.
- [ ] Mantener lista `active-sessions-{userId}` con TTL furthest session.
- [x] `findSession`, `findSessions` desde secondary storage o DB join.
- [ ] Parsear fechas recuperadas de secondary storage.
- [ ] `updateSession` actualiza secondary storage, DB y lista activa.
- [ ] `deleteSession`, `deleteSessions` limpian secondary storage y DB segun `storeSessionInDatabase`/`preserveSessionInDatabase`.
- [ ] `findOAuthUser` busca primero account provider/accountId, luego email.
- [x] `findUserByEmail` con includeAccounts opcional.
- [x] `findUserById`.
- [ ] `linkAccount`.
- [ ] `updateUser` y `updateUserByEmail` refrescan sesiones cacheadas del usuario.
- [x] `updatePassword` en account provider `credential`.
- [ ] `findAccounts`, `findAccount`, `findAccountByProviderId`, `findAccountByUserId`.
- [ ] `updateAccount`.
- [ ] Verification values con identifier plain/hashed/custom hash.
- [ ] Config de storeIdentifier con default y overrides por prefix.
- [ ] Verification en secondaryStorage con key `verification:{identifier}` y TTL.
- [ ] Verification fallback a DB si `storeInDatabase`.
- [ ] Cleanup de verification expirados salvo `disableCleanup`.
- [ ] Update/delete verification en cache y DB.
- [ ] Parse input adicional con required/default/input false/validator/transform.
- [ ] Bloquear campos `input=false` si el usuario intenta setearlos.
- [x] Filtrar output user/session/account; nunca devolver tokens/password de account.
- [ ] Cachear schemas parseados por opciones/modelo/modo.
- [ ] Merge de schema de plugins y renombres `modelName`/`fieldName`.
- [x] Generar schema fisico con field names, references y order.
- [ ] Migraciones: detectar tablas faltantes y columnas faltantes.
- [ ] Migraciones: mapear tipos por postgres/mysql/sqlite/mssql.
- [ ] Migraciones: detectar schema postgres desde `search_path`.
- [ ] Migraciones: filtrar tablas del schema postgres correcto.
- [ ] Migraciones: crear indexes/unique indexes despues de tablas.
- [ ] Migraciones: soportar id default string, uuid o serial.
- [ ] Migraciones: compilar SQL y ejecutar migraciones.
- [ ] Equivalente Rust a `toZodSchema` como validacion/metadata schema para servidor/OpenAPI.
- [ ] Pruebas de DB, internal-adapter, secondary-storage, migration schema, schema validation y instrumentation DB.

## OAuth state, account linking y social sign-in

- [ ] Generar OAuth state con random 32 y PKCE code verifier 128.
- [ ] Guardar `callbackURL`, `errorURL`, `newUserURL`, `link`, `expiresAt`, `requestSignUp` y additionalData permitido.
- [ ] Proteger campos reservados para que `additionalData` no sobreescriba codeVerifier/expires/callback/link/requestSignUp.
- [ ] State strategy `cookie`: cifrar payload en cookie `oauth_state`, incluir oauthState y borrar al parsear.
- [ ] State strategy `database`: signed cookie `state` + verification record.
- [ ] Soportar `skipStateCookieCheck` solo para casos justificados como oauth-proxy/SAML relay state.
- [ ] Validar mismatch, invalid decrypt/parse, missing verification, expired state.
- [ ] Mapear state errors a redirects seguros.
- [ ] Guardar OAuth state en request state para hooks after.
- [ ] En callback, buscar usuario OAuth por provider account antes que email.
- [ ] Linkear cuenta si provider es trusted o email verificado y accountLinking permite.
- [ ] Respetar `disableImplicitLinking`, `accountLinking.enabled=false`.
- [ ] Actualizar `emailVerified` si provider verifica el email actual.
- [ ] `overrideUserInfoOnSignIn` actualiza user desde provider.
- [ ] `updateAccountOnSignIn=false` evita sobrescribir tokens.
- [ ] Cifrar OAuth tokens en DB si `encryptOAuthTokens`.
- [ ] Detectar tokens cifrados por envelope/hex antes de decrypt.
- [ ] Crear usuario+account transaccional para nuevos OAuth users.
- [ ] Enviar email verification en signup OAuth si email no verificado y config lo pide.
- [ ] Crear sesion despues de OAuth success.
- [ ] Soportar sign-in social con redirect URL y callback URL seguros.
- [ ] Soportar sign-in social por `idToken` sin redirect donde provider lo permita.
- [ ] Soportar refresh access token por account/provider.
- [ ] Soportar multi-client-id en providers que lo permiten; usar primero para auth URL y validar audiencia.
- [ ] Pruebas de social flow, async provider, redirect URI inferido/custom, disable signup, disable implicit signup, additionalData, token refresh, updateAccountOnSignIn, Apple/Vercel/multi-client IDs.

## Social providers

- [ ] El paquete principal solo re-exporta providers desde core upstream; en OpenAuth re-exportarlos desde `openauth` con feature `oauth`.
- [ ] Implementar providers en crate/modulo OAuth, no en fachada.
- [ ] Cubrir provider config comun: `clientId`, `clientSecret/clientKey`, `redirectURI`, scopes, prompt, accessType, enabled.
- [ ] Cubrir `mapProfileToUser`.
- [ ] Cubrir `verifyIdToken` cuando aplique.
- [ ] Cubrir provider-specific auth/token/userinfo endpoints.
- [ ] Cubrir Apple: nombre desde `user` POST/idToken body, sin fallback email como name.
- [ ] Cubrir Google: JWKS/id token audience con multiples client IDs.
- [ ] Cubrir Vercel: PKCE, userinfo y `preferred_username` fallback.
- [ ] Cubrir providers listados en core plan previo y re-export desde main.
- [ ] Tests de providers en paquete principal y tests de utils/providers en crate OAuth.

## Plugins: sistema comun

- [ ] Contrato plugin con `id`, endpoints, hooks, schema, init, middlewares, rateLimit y error codes.
- [ ] Plugin init puede devolver opciones adicionales y contexto adicional.
- [ ] Plugin trusted origins se fusionan con origenes del usuario.
- [ ] Plugin DB hooks se etiquetan como `plugin:<id>`.
- [ ] Plugin endpoints pasan por el mismo wrapper de auth endpoints.
- [ ] Plugin middlewares se envuelven con contexto auth y spans.
- [ ] Plugin rateLimit participa en reglas por path.
- [ ] Plugin schema participa en migraciones, parse input/output y adapters.
- [ ] Tests por plugin deben cubrir comportamiento servidor principal, no client-only.

## Plugins: checklist individual

- [ ] `access`: access control statements, permisos y tests.
- [ ] `additional-fields`: campos adicionales y tests; client helper queda excluido.
- [ ] `admin`: schema, permisos, roles, ban/unban, create/update/remove user, sessions, impersonation, set password, has-permission, tests.
- [ ] `anonymous`: sign-in anonymous, delete/convert anonymous user, schema/error codes, tests.
- [ ] `bearer`: bearer token/session auth, tests.
- [ ] `captcha`: providers de verificacion CaptchaFox, Turnstile, reCAPTCHA, hCaptcha; hooks/endpoints protegidos; tests.
- [ ] `custom-session`: override de get-session y custom payload, tests.
- [ ] `device-authorization`: device code, token polling, verify, approve, deny, schema/error codes, tests.
- [ ] `email-otp`: send/check/verify email OTP, sign-in OTP, password reset OTP, email change OTP, rate limits, schema, tests.
- [ ] `generic-oauth`: providers generic OAuth, sign-in, callback, link, provider presets Auth0/Gumroad/HubSpot/Keycloak/Line/Okta/Patreon/Slack, tests.
- [ ] `haveibeenpwned`: password breach check integration, tests.
- [ ] `jwt`: JWKS, token endpoint, sign/verify JWT, key rotation, schema/adapter, tests.
- [ ] `last-login-method`: store/update last login method, custom prefix, optional DB storage, tests.
- [ ] `magic-link`: sign-in magic link, verify, callback/session creation, rate limit, tests.
- [ ] `mcp`: OAuth authorization-server metadata, protected resource metadata, authorize/token/register/get-session, client auth helpers, tests.
- [ ] `multi-session`: list device sessions, set active, revoke device session, tests.
- [ ] `oauth-proxy`: proxy callback, relaxed state cookie check where required, tests.
- [ ] `oidc-provider`: discovery, authorize, consent, token, userinfo, dynamic client registration, get client, end session, prompt utils, schema, tests.
- [ ] `one-tap`: one-tap callback, tests if server behavior is present.
- [ ] `one-time-token`: generate/verify one-time token, utils, tests.
- [ ] `open-api`: generate OpenAPI schema, reference endpoint, generator/model schema, tests.
- [ ] `organization`: org CRUD, member CRUD, invitation flows, team CRUD, active org/team, roles/access control, adapter, hooks, permissions, tests.
- [ ] `phone-number`: sign-in phone, send OTP, verify, password reset, schema/rate limit, tests.
- [ ] `siwe`: nonce, verify SIWE message, wallet schema, tests.
- [ ] `test-utils`: server-side test helpers/factories/cookie builder/OTP sink only; no production dependency.
- [ ] `two-factor`: enable/disable, TOTP, OTP, backup codes, verification flow, rate limits, schema, tests.
- [ ] `username`: sign-in username, availability, validation, schema/error codes, tests.

## Plugin endpoint inventory

- [ ] OpenAPI: `/open-api/generate-schema`, reference endpoint.
- [ ] Username: `/sign-in/username`, `/is-username-available`.
- [ ] Custom session: `/get-session` override.
- [ ] SIWE: `/siwe/nonce`, `/siwe/verify`.
- [ ] Anonymous: `/sign-in/anonymous`, `/delete-anonymous-user`.
- [ ] One-time token: `/one-time-token/generate`, `/one-time-token/verify`.
- [ ] Multi-session: `/multi-session/list-device-sessions`, `/multi-session/set-active`, `/multi-session/revoke`.
- [ ] OAuth proxy: `/oauth-proxy-callback`.
- [ ] Magic link: `/sign-in/magic-link`, `/magic-link/verify`.
- [ ] JWT: `/jwks` or equivalent JWKS endpoint, `/token`, sign/verify endpoints.
- [ ] Two-factor: `/two-factor/enable`, `/two-factor/disable`, `/two-factor/get-totp-uri`, `/two-factor/verify-totp`, `/two-factor/send-otp`, `/two-factor/verify-otp`, `/two-factor/verify-backup-code`, `/two-factor/generate-backup-codes`, view backup codes.
- [ ] Device authorization: `/device/code`, `/device/token`, `/device`, `/device/approve`, `/device/deny`.
- [ ] MCP: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/mcp/authorize`, `/mcp/token`, `/mcp/register`, `/mcp/get-session`.
- [ ] One-tap: `/one-tap/callback`.
- [ ] OIDC provider: `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/register`, `/oauth2/client/:id`, `/oauth2/endsession`.
- [ ] Generic OAuth: `/sign-in/oauth2`, `/oauth2/callback/:providerId`, `/oauth2/link`.
- [ ] Admin: `/admin/set-role`, `/admin/get-user`, `/admin/create-user`, `/admin/update-user`, `/admin/list-users`, `/admin/list-user-sessions`, `/admin/unban-user`, `/admin/ban-user`, `/admin/impersonate-user`, `/admin/stop-impersonating`, `/admin/revoke-user-session`, `/admin/revoke-user-sessions`, `/admin/remove-user`, `/admin/set-user-password`, `/admin/has-permission`.
- [ ] Organization org: `/organization/create`, `/organization/check-slug`, `/organization/update`, `/organization/delete`, `/organization/get-full-organization`, `/organization/set-active`, `/organization/list`.
- [ ] Organization team: `/organization/create-team`, `/organization/remove-team`, `/organization/update-team`, `/organization/list-teams`, `/organization/set-active-team`, `/organization/list-user-teams`, `/organization/list-team-members`, `/organization/add-team-member`, `/organization/remove-team-member`.
- [ ] Organization roles: `/organization/create-role`, `/organization/delete-role`, `/organization/list-roles`, `/organization/get-role`, `/organization/update-role`.
- [ ] Organization invites: `/organization/invite-member`, `/organization/accept-invitation`, `/organization/reject-invitation`, `/organization/cancel-invitation`, `/organization/get-invitation`, `/organization/list-invitations`, `/organization/list-user-invitations`.
- [ ] Organization members: `/organization/remove-member`, `/organization/update-member-role`, `/organization/get-active-member`, `/organization/leave`, `/organization/list-members`, `/organization/get-active-member-role`, `/organization/has-permission`.
- [ ] Phone number: `/sign-in/phone-number`, `/phone-number/send-otp`, `/phone-number/verify`, `/phone-number/request-password-reset`, `/phone-number/reset-password`.
- [ ] Email OTP: `/email-otp/send-verification-otp`, `/email-otp/check-verification-otp`, `/email-otp/verify-email`, `/sign-in/email-otp`, `/email-otp/request-password-reset`, `/forget-password/email-otp`, `/email-otp/reset-password`, `/email-otp/request-email-change`, `/email-otp/change-email`.

## Adapters y migraciones externas

- [x] Main package debe re-exportar adapter factory y helpers de naming.
- [ ] Mantener alias deprecated solo si aporta compatibilidad real; si no, documentar migration path Rust.
- [ ] Memory adapter como dependencia de test/dev o fallback explicito.
- [ ] SQL adapter(s) Rust detras de features, no siempre instalados.
- [ ] Mongo adapter en crate/feature propio.
- [ ] No portar Prisma/Drizzle/Kysely como dependencias Rust; usar sus contratos como referencia de adapter behavior.
- [ ] Tests de adapter factory y adapters concretos deben vivir por crate/feature.

## Utils servidor

- [ ] URL helpers: protocolo obligatorio, path base, env fallback, origin/host/protocol extraction.
- [ ] Validar proxy headers antes de confiar en `x-forwarded-host`/`x-forwarded-proto`.
- [ ] Dynamic baseURL con host allowlist y wildcards.
- [ ] Request-like detection equivalente para integraciones HTTP Rust.
- [x] Wildcard matching para origins/rate limit.
- [x] IP extraction y normalization.
- [ ] Time/date helpers (`sec`, `getDate`) equivalentes.
- [ ] Boolean parsing donde el API acepta coercion.
- [ ] Hide metadata helper si se mantiene OpenAPI/plugin metadata.
- [ ] Middleware response helper.
- [ ] Tests de URL utils y request/proxy edge cases.

## Instrumentacion y telemetry

- [ ] Spans de endpoints con route y operationId.
- [ ] Spans de handler.
- [ ] Spans de hooks before/after con source user/plugin.
- [ ] Spans de DB hooks con model y operation.
- [ ] Instrumentation endpoint tests.
- [ ] Instrumentation DB tests.
- [ ] Telemetry config extraida desde opciones sin enviar secretos.
- [ ] Telemetry feature-gated y apagable.

## Test-utils servidor

- [ ] Test instance helper para levantar auth con memory DB.
- [ ] Cookie setter/parser para flujos multi-request.
- [ ] Factories de user/session/account/verification.
- [ ] DB helpers para limpiar/sembrar datos.
- [ ] OTP sink para plugins OTP.
- [ ] Auth helpers para sesiones y headers.
- [ ] Mantener test-utils fuera de produccion o bajo feature `test-utils`.

## Tests upstream que deben mapearse

- [ ] API: check endpoint conflicts, index/router, middlewares authorization/origin, rate-limiter, to-auth-endpoints.
- [ ] API routes: account, email-verification, error, password, session-api, sign-in, sign-out, sign-up, update-user.
- [ ] Auth: full, minimal, trusted-origins.
- [ ] Call/direct API behavior.
- [ ] Context: create-context, init, init-minimal.
- [x] Cookies.
- [x] Crypto: password, secret rotation.
- [ ] DB: db, internal-adapter, secondary-storage, get-migration-schema, to-zod.
- [ ] Instrumentation: DB y endpoint.
- [ ] OAuth2: link-account, utils.
- [ ] Social providers: social flow, provider specifics, redirect URI, token refresh.
- [ ] Types: adaptar como compile-time Rust API tests o doctests cuando aplique.
- [x] Utils: URL tests.
- [ ] Plugins: un test suite por plugin servidor listado arriba.
- [ ] Excluir client tests salvo que validen contrato HTTP reusable.
- [ ] Excluir framework integration tests salvo que revelen requirement servidor.

## Exclusiones y diferidos

- [ ] No portar `src/client/*` al core Rust.
- [ ] No portar stores React/Solid/Vue/Svelte/Lynx.
- [ ] No portar `nanostores`, focus manager, online manager, broadcast channel.
- [ ] No portar proxy client/parser/path-to-object salvo como referencia para futuros SDKs HTTP.
- [ ] No portar Next.js/SvelteKit/SolidStart/TanStack integrations al core.
- [ ] No portar plugin `client.ts` files al core; solo usar sus endpoints esperados como referencia.
- [ ] No replicar tipos TS de inferencia avanzada; traducir a API Rust explicita.
- [ ] Client SDKs futuros deben ser wrappers HTTP pequenos o generados desde OpenAPI.

## Mejoras permitidas sobre upstream

- [ ] Separar aun mas modulos grandes: `api/routes`, `db/internal_adapter`, `plugins/organization`, `plugins/oidc_provider`.
- [ ] Usar tipos Rust para estados invalidos: secrets validados, URLs confiables, session token, provider id.
- [ ] Hacer errores exhaustivos y publicos donde ayuden a manejar fallos.
- [ ] Usar crypto crates mantenidos y auditables; preferir Argon2id para passwords si no rompe objetivos.
- [ ] Requerir configuracion explicita para confiar en proxy headers en produccion.
- [ ] Reducir globals mutables; inyectar clocks, random y HTTP client para tests.
- [ ] Hacer rate limit storage atomico cuando el backend lo permita.
- [ ] Evitar cache memory global no namespaced para multi-tenant/serverless.
- [ ] Hacer OpenAPI generado desde el mismo registro tipado de endpoints.
- [ ] Mantener adapters y plugins bajo features para no inflar build/dependencias.
- [ ] Documentar cualquier decision donde OpenAuth mejore seguridad aunque difiera de Better Auth.

## Criterios de completado

- [ ] La fachada `openauth` permite instalar y usar la libreria principal sin conocer crates internos.
- [ ] La logica servidor vive en crates/modulos especializados, no en la fachada.
- [ ] Todos los endpoints servidor base tienen equivalente Rust tipado y tests.
- [ ] Cookies, secrets, session cache, OAuth state y token encryption tienen tests de seguridad.
- [ ] DB/internal adapter cubre sesiones, accounts, users, verification, hooks y secondary storage.
- [ ] Plugins servidor tienen checklist y tests por comportamiento observable.
- [ ] Social/OAuth cubre redirect, callback, id token, PKCE, refresh, linking y provider specifics.
- [ ] Browser-only queda documentado como diferido/excluido.
- [ ] Cualquier comportamiento mejorado esta documentado y cubre la intencion upstream.
