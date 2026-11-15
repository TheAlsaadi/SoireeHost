# Vendored OWASP Core Rule Set

The request rules of CRS v4.30.0 and the data files they use, copied byte for byte from
the signed official release (`build/crs.lock`). Do not edit these files: `build/check-crs.ps1`
fails CI if they differ from the release. To move to a new release, update `build/crs.lock`
and `internal/waf/crs.go`, then run `powershell -File build\check-crs.ps1 -Update`.

Licensed under the Apache License 2.0 (`LICENSE` in this folder). See ADR-0008.
