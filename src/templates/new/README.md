# {{name}}

A vynkor plugin scaffolded by [`vynm new`](https://github.com/vynkor-core/vynkor-manager).

## Build

```bash
cargo build
```

## Package & publish

```bash
# from the plugins repo:
scripts/package.sh {{name}}
# then sign the registry entry:
vynm sign --key <keyfile> --slug {{name}} --version <v> --sha256 <h> \
  --archive-url <url> --min 0.1.0
```
