# Shapoclyack — краткая карта для Claude

Платформа сканирования сети и управления уязвимостями: control plane на FastAPI,
сенсоры-сканеры, консоль на Next.js, развёртывание в k8s (kind локально).

## Где что лежит

- `api/` — FastAPI: `routes/` (маршруты), `services/` (логика), `db/` (модели, `db/migrations/` — Alembic, `alembic -c api/db/alembic.ini upgrade head`), `settings.py`.
- `scanner/` — пайплайн сканирования (`pipeline/`, `inputs/`, `output/`, `scheduler.py`, `main.py`).
- `agent/` — пакет **сенсора** (узел сканирования; `worker.py`). «Агент» в разговоре = Windows-агент Lariska, отдельный репозиторий.
- `recon/` — Go-модуль разведки.
- `web-next/` — консоль Next.js (`src/app`, `src/components`, `src/lib`); `npm run typecheck|lint|test`.
- `k8s/` — Kustomize; проверка `bash k8s/scripts/validate-kustomize.sh`.
- `tests/` — pytest; `docs/` — тематические документы, `docs/adr/` — решения.

## Проверки

- Линт: `scripts/ci-lint.sh` (ruff ровно той версии, что в `requirements-dev.txt`).
- Тесты: `python -m pytest tests/test_<area>.py -q` — запускай **только затронутые файлы**, не весь набор.
- Полный прогон с Postgres/NATS — `scripts/ci-pytest.sh` (нужны `OCTO_POSTGRES_URL`, `OCTO_NATS_URL`); без них ~40% тестов молча пропускается.
- Подробности — `docs/development.md` (читать нужный раздел, не целиком).

## Экономия контекста

- **Не читай целиком** `README.md`, `ROADMAP.md`, `CHANGELOG.md`: `grep -n` по ключевому слову, затем `sed -n` узкий диапазон.
- Не читай транскрипты прошлых сессий (`~/.claude/projects/**.jsonl`) и большие логи Jenkins целиком — `grep`/`tail`.
- Файлы > 300 строк читай кусками вокруг нужного места.
- Вывод команд обрезай (`| tail -40`, `-q`, `--tb=short`).
- Субагенты дорогие (каждый стартует с ~55K токенов): поиск — сам через `grep` или `Explore`; не больше 3–5 агентов на задачу, workflow — только по явной просьбе.

## Правила

- Ответы пользователю — по-русски; коммиты и PR — по-английски.
- `main` защищён: работа в ветке, влитие через PR. Репозиторий публичный — никаких секретов, списков целей сканирования и данных об активах.
