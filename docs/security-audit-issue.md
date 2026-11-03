# Security Audit: Remediation Recommendations (3 Issues)

> Результат аудита безопасности (ветка `main`, коммит `5ee0ad1`). Ниже — три issue
> с рекомендациями, отранжированных по приоритету. Каждый пункт содержит ссылку на
> конкретный код, обоснование и критерий приёмки.

---

## Issue #1 — [HIGH] TLS-верификация отключена при HTTPS-подтверждении subdomain takeover

**Компонент:** `scanner/pipeline/takeover.py`
**Место:** строка 430 (`_confirm_all`)

```python
async with httpx.AsyncClient(
    headers={"User-Agent": USER_AGENT},
    verify=False,          # ← TLS не проверяется
    follow_redirects=False,
    trust_env=False,
) as client:
```

**Обоснование.** Docstring модуля (строки 30–38) сознательно обосновывает `verify=False`:
у незанятого ресурса у провайдера нет сертификата под имя жертвы. Это верная причина для
*первичного* запроса, но отключение проверки на всём клиенте открывает MITM на этапе
подтверждения уязвимости: злоумышленник, контролирующий путь, может подменить ответ
провайдера как в сторону ложного «vulnerable» (фейковые finding'и, паника у клиента),
так и в сторону ложного «claimed» (реальный takeover скрывается). Ответ подтверждения —
это security-relevant вывод, и он не должен основываться на непроверенном соединении.

**Рекомендация.**
1. Не отключать верификацию глобально: использовать `verify=True` по умолчанию.
2. Для случая «нет сертификата под имя» различать ошибки: `ssl.SSLCertVerificationError`
   с кодом `CERTIFICATE_UNKNOWN`/unknown-ca допустим и означает «сертификат провайдера не
   подходит имени» — это сигнал продолжать проверку по HTTP-отпечатку; любые прочие TLS-
   ошибки (handshake failure, expired, hostname mismatch при валидном CA-chain) должны
   помечать попытку как inconclusive, а не vulnerable.
3. Альтернатива проще: подтвердить takeover только по DNS-признаку (NXDOMAIN target) либо
   по HTTP-ответу на порту 80; HTTPS-запрос с непроверенным TLS использовать как
   дополнительный сигнал пониженной достоверности, фиксируя в finding флаг
   `tls_verified: false`.
4. Добавить регрессионный тест: mock-провайдер с самоподписанным сертификатом → finding
   получает `tls_verified: false`; MITM-сценарий (другой fingerprint при том же имени) →
   статус inconclusive.

**Критерий приёмки:** в `_confirm_all` нет unconditional `verify=False`; каждый finding из
takeover-стадии несёт поле `tls_verified`; CI-тест покрывает оба сценария.

---

## Issue #2 — [HIGH] Прод-валидация API не проверяет SQLite-fallback и placeholder-секреты; Helm-секреты формально опциональны

**Компоненты:** `api/settings.py`, `k8s/scripts/validate-kustomize.sh`, `charts/shapoclyack/values.yaml`
**Места:**
- `api/settings.py:2048` — дефолт CORS `"*"` (см. также Issue #3);
- `api/settings.py` (~2056) — `postgres_url_env` хранится только локально, для сообщения об ошибке;
- `charts/shapoclyack/values.yaml:144-148` — `existingSecrets.*` пустые строки по умолчанию;
  защита держится только на `devPlaceholders: false` + отказе рендера;
- `k8s/shapoclyack/overlays/prod-ha/kustomization.yaml:12` — декларировано «fail loudly rather
  than defaults that fail quietly», но `validate-kustomize.sh` не grep'ит rendered-манифесты на
  публичные dev-placeholder'ы из kustomize base.

**Обоснование.** Postgres — жёсткая зависимость (tenants, users, assets, jobs, agents, webhooks).
SQLite-fallback подменяет отсутствующий `OCTO_POSTGRES_URL` локальным файлом: runtime-отказ
(`settings.py:~1760`) есть, но статической проверки в CI/deploy-пайплайне прод-оверлея нет —
mis-deploy заметят только по потере данных мульти-тенантности. Аналогично с секретами: если
оператор задаст `devPlaceholders: true` «временно» или создаст Secret со значением из примера,
ни один валидатор это не поймает — плейсхолдеры публично опубликованы в репозитории.

**Рекомендация.**
1. В `k8s/scripts/validate-kustomize.sh` для оверлеев `prod-*` добавить проверки
   `kustomize build | grep`:
   - отсутствие строк-плейсхолдеров БД/NATS/ClickHouse/JWT из base (захардкодить список
     значений-маркеров, синхронизировать с `k8s/shapoclyack/examples/api-secrets.example.yaml`);
   - отсутствие `OCTO_POSTGRES_URL` со значением `sqlite:` / пустым;
   - наличие всех ключей Secret, на которые ссылаются deployment'ы (`secretKeyRef`), иначе
     `kubectl apply` падает только при старте пода.
2. В Helm-чарте сделать `existingSecrets.postgres/clickhouse/nats/jwt` обязательными через
   `required` в шаблонах (сейчас отказ основан на значении флага `devPlaceholders` — флаг
   легче случайно включить, чем забыть обязательное поле).
3. Зафиксировать контракт: значения из `api-secrets.example.yaml` добавить в CI-таргет
   (`make ci-*` / Jenkinsfile publish), чтобы PR с новым плейсхолдером в base не прошёл без
   обновления списка детекта.

**Критерий приёмки:** `validate-kustomize.sh prod-ha` падает на (а) placeholder-пароле,
(б) `sqlite:` URL, (в) висячем `secretKeyRef`; helm template без `existingSecrets.jwt`
падает с `required`-ошибкой даже при `devPlaceholders=true` для prod-values.

---

## Issue #3 — [MEDIUM] Дефолт `OCTO_API_CORS` = `"*"` вместо явного отказа от конфигурации

**Компонент:** `api/settings.py`
**Место:** строки 2048–2049

```python
origins = os.environ.get("OCTO_API_CORS", "*").strip()
cors = [part.strip() for part in origins.split(",") if part.strip()] or ["*"]
```

**Обоснование.** Строгий режим (`_strict_problems`, ~1746) корректно refuses `"*"` в prod —
но защита существует только потому, что дефолт небезопасен. Три пути открыть API любому
origin: не задать переменную, задать пустое значение (ветвление `or ["*"]`), задать
`"*", https://x` (детект ловит любой `"*"` в списке — верно, но сам дефолт провоцирует).
Безопаснее «fail closed»: незаданный CORS должен означать «никаких внешних origins», а
консоль работает за тем же origin (same-origin запросы CORS не требуют).

**Рекомендация.**
1. Сменить дефолт на пустой список: `os.environ.get("OCTO_API_CORS", "")` → `cors == []`
   (CORSMiddleware с `allow_origins=[]` пропускает только same-origin).
2. Сохранить обратную совместимость для dev: в `compose.*.yml` и оверлее `dev` явно выставить
   `OCTO_API_CORS=*`; в strict-валидации сообщение переформулировать с «default when unset»
   на «explicitly set to *».
3. Убрать ветвление `or ["*"]` (пустая строка → пустой список, а не wildcard).
4. Обновить `docs/operations.md` и комментарий в `api/app.py:498` (CORS-safelist для
   кастомных заголовков консоли), чтобы документация не противоречила новому дефолту.

**Критерий приёмки:** контейнер API без `OCTO_API_CORS` отвечает 403 на preflight с чужого
origin; dev-compose поднимается с `*`; тесты `tests/` на settings обновлены; ни один prod
манифест не полагается на implicit wildcard.

---

## Сводка приоритетов

| # | Риск | Severity | Блок | Оценка усилий |
|---|------|----------|------|---------------|
| 1 | MITM на подтверждении takeover | HIGH | scanner | S–M |
| 2 | Плейсхолдеры/fallback в проде | HIGH | deploy/CI | M |
| 3 | Wildcard CORS по умолчанию | MEDIUM | api | S |

Рекомендуемый порядок: #3 (быстрый, снижает surface) → #2 (защита деплоя) → #1 (требуется дизайн статуса `inconclusive`).
