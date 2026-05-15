# Admin Plugin Parity Completion Plan

## Summary
Completar los gaps server-side del plugin `openauth-plugins::admin` contra Better Auth upstream, priorizando seguridad, compatibilidad observable y tests. La implementacion debe mantenerse modular: antes de tocar mas `routes.rs`, extraer documentacion OpenAPI a `admin/openapi.rs` para que ningun archivo pase ~500 lineas.

## Implementation Checklist
- [x] Extraer OpenAPI a `admin/openapi.rs` y dejar `routes.rs` bajo margen comodo.
- [x] Escribir tests fallidos para seguridad de `create-user`, `data`, password vacio y filtros tipados.
- [x] Implementar validaciones y parsing tipado.
- [x] Escribir tests fallidos para impersonacion admin y `/list-sessions`.
- [x] Implementar after hook de filtrado de sesiones impersonadas.
- [x] Escribir tests fallidos para `has-permission` edge cases y roles multiples/inexistentes.
- [x] Implementar ajustes de permisos/errores.
- [x] Evaluar request-path en DB hook; implementar si permite cubrir callback ban sin una refactorizacion mayor.
- [x] Correr verificacion completa y revisar tamanos.

## Verification
- `cargo test -p openauth-plugins`
- `cargo test -p openauth-core`
- `cargo fmt --check`
- `cargo clippy -p openauth-core --all-targets -- -D warnings`
- `cargo clippy -p openauth-plugins --all-targets -- -D warnings`
- `git diff --check`
- `wc -l` sobre admin/core files relevantes
