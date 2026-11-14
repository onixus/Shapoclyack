# Product license generator / Генератор продуктовой лицензии

Offline Ed25519 signer for `shapoclyack-license` v1. The **private seed never
ships** in the product image; the control plane verifies with a pinned public
key (`OCTO_LICENSE_PUBLIC_KEY`).

Офлайн-подпись лицензий Ed25519. **Приватный ключ не входит** в образ продукта;
control plane проверяет подпись закреплённым публичным ключом.

See also: `docs/adr/0007-product-licensing.md`.

## Run / Запуск

From the repository root (`PYTHONPATH=.`):

```bash
cd /path/to/repo
PYTHONPATH=. python -m tools.license_gen --help
```

## Keypair (vendor ops) / Пара ключей

```bash
PYTHONPATH=. python -m tools.license_gen --generate-keypair -o keys.json
# Keep signing_key_base64 secret. Pin public_key_base64 as OCTO_LICENSE_PUBLIC_KEY.
```

Print the public key for an existing seed (file or `OCTO_LICENSE_SIGNING_KEY`):

```bash
echo '<base64-or-hex-seed>' > /tmp/seed.txt
PYTHONPATH=. python -m tools.license_gen --signing-key /tmp/seed.txt --print-public-key
# or:
export OCTO_LICENSE_SIGNING_KEY='...'
PYTHONPATH=. python -m tools.license_gen --print-public-key
```

In the product / в продукте:

```bash
export OCTO_LICENSE_PUBLIC_KEY='<public_key_base64 from --print-public-key>'
export OCTO_LICENSE_ENFORCEMENT_ENABLED=true   # when ready to enforce
```

## Duration calculator / Калькулятор срока

Exactly one of `--days` / `--months` / `--years` / `--until` is required.
Months and years are **calendar** steps (31 Jan + 1 month → last day of Feb).

Ровно один из флагов срока. Месяцы и годы — календарные (31 янв + 1 мес → конец февраля).

```bash
export OCTO_LICENSE_SIGNING_KEY='...'   # or --signing-key /path/to/seed

# 30 days from now
PYTHONPATH=. python -m tools.license_gen \
  --customer "Acme Corp" --days 30 --lariska --brand-watch -o acme.license.json

# One calendar year from a fixed start
PYTHONPATH=. python -m tools.license_gen \
  --customer "Acme Corp" --valid-from 2026-01-31T00:00:00Z --years 1 \
  --signing-key ./seed.txt

# Absolute end
PYTHONPATH=. python -m tools.license_gen \
  --customer "Acme Corp" --until 2027-12-31T23:59:59Z --no-lariska
```

Feature flags: `--lariska` / `--no-lariska` (default on), `--brand-watch` /
`--no-brand-watch` (default off).

## Upload / Загрузка

Platform admins upload the signed JSON via `POST /api/license`. Status:
`GET /api/license`.
