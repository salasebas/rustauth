# Generic OAuth Closeout Checklist

## Mantener mantenible
- [x] Dividir `crates/openauth-plugins/tests/generic_oauth/mod.rs` en módulos pequeños.
- [x] Mantener cada archivo de implementación `src/generic_oauth/**` razonablemente corto; extraer módulos si una responsabilidad se mezcla o crece demasiado.

## Paridad de params y config
- [x] Hacer que `token_url_params` pueda sobrescribir defaults del token request, igual que upstream.
- [x] Añadir params dinámicos por request para authorization/token URL mediante callbacks Rust.
- [x] Añadir validación explícita de configuración para provider id vacío, client id vacío, endpoints faltantes y issuer requerido.
- [x] Mapear errores de validación/discovery a códigos específicos (`TOKEN_URL_NOT_FOUND`, `INVALID_OAUTH_CONFIG`, etc.).

## Discovery y refresh
- [x] Resolver discovery para refresh-token en el provider cuando solo existe `discovery_url`.
- [x] Añadir test de refresh discovery-only.

## Rutas y pruebas restantes
- [x] Callback con `error` query y `error_description`.
- [x] Error callback URL que ya trae query params.
- [x] Issuer missing requerido.
- [x] Link account email mismatch.
- [x] Link account actualiza cuenta existente del mismo usuario.
- [x] Token exchange HTTP real con `authorization_headers`.
- [x] Token/userinfo HTTP real con servidor JSON local.

## Verificación final
- [x] `cargo test -p openauth-plugins generic_oauth`
- [x] `cargo test -p openauth-plugins`
- [x] `cargo test -p openauth-core social`
- [x] `cargo fmt`
- [x] Commit final con hooks verdes.
