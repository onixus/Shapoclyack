// Локальный Jenkins (http://localhost:8081) — порт .github/workflows/ci.yml.
// Все стадии крутятся в контейнерах через docker.sock хоста, поэтому на
// контроллере не нужны ни Python, ни Node, ни kubectl.
//
// Отличия от GitHub Actions, осознанные:
//   * нет cache-from/to type=gha — вместо него локальный кэш демона + именованные
//     volume'ы под pip/npm;
//   * synthetic-load-test (composite action) не портирован — см. stage 'Load test';
//   * образ собирается только под нативный linux/arm64, без QEMU-матрицы.

def PIP_CACHE = '-v shapoclyack-pip-cache:/root/.cache/pip'

// Уникально на джобу, а не только на номер билда. В multibranch у каждой
// ветки своя нумерация с #1, поэтому общий тег означал бы, что параллельные
// сборки разных веток перетирают друг другу образ, а Smoke/E2E/Trivy молча
// проверяют чужой — это хуже падения. disableConcurrentBuilds() тут не
// помогает: он про одну джобу, а ветки это разные джобы.
def CI_SLUG = "${env.JOB_NAME}-${env.BUILD_NUMBER}".replaceAll(/[^A-Za-z0-9]+/, '-').toLowerCase()
def IMAGE_TAG = "network-scan-cli:ci-${CI_SLUG}"

pipeline {
  agent none

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timeout(time: 90, unit: 'MINUTES')
  }

  stages {
    stage('Lint (ruff)') {
      agent { docker { image 'python:3.12-slim'; args PIP_CACHE; reuseNode true } }
      steps {
        sh '''
          set -eu
          pip install --quiet ruff==0.15.22
          ruff check scanner api tests
        '''
      }
    }

    // Quality gate. Стоит до тестов и сборки образа намеренно: находка
    // уровня ERROR роняет билд за пару минут, а не после часа сборки.
    stage('SAST (semgrep)') {
      agent any
      steps {
        sh '''
          set -eu
          RULES="--config p/security-audit --config p/secrets --config p/python"

          # Проход 1 — полный отчёт, все severity, билд не роняет (--no-error).
          # WARNING/INFO должны быть видны в артефакте, но не блокировать.
          echo "[sast] полный отчёт"
          docker run --rm -v "$WORKSPACE":/src -w /src semgrep/semgrep:latest \
            semgrep scan $RULES --metrics=off --no-error \
              --json --output semgrep.json

          # Проход 2 — гейт. --severity ERROR оставляет только криты,
          # --error переводит находки в ненулевой код возврата. Гейтим кодом
          # возврата, а не разбором JSON: меньше движущихся частей.
          echo "[sast] quality gate: блок при ERROR"
          docker run --rm -v "$WORKSPACE":/src -w /src semgrep/semgrep:latest \
            semgrep scan $RULES --metrics=off --severity ERROR --error
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
        }
      }
    }

    stage('Tests') {
      // Матрица развёрнута в последовательный цикл намеренно. Параллельные
      // ячейки получали каждая свой воркспейс и клонировали репозиторий
      // одновременно, и этот клон перемежающимся образом падал с
      // "inflate: data stream error" ещё на 154 объектах: git fsck исходного
      // репозитория чист, мелкий клон не помог, а в изоляции (хост и контейнер,
      // bind-mount и ФС контейнера, параллельно и по одному) 12 попыток прошли
      // без единого сбоя. Один агент — один воркспейс — один чекаут, и целый
      // класс гонок исчезает. Цена — около трёх минут: прогоны идут по очереди.
      agent any
      steps {
        script {
          for (PY in ['3.11', '3.12']) {
            try {
              // Своя сеть на прогон: postgres и nats резолвятся по alias'ам.
              // 127.0.0.1 из GitHub Actions тут не работает — у каждого
              // контейнера свой netns, общего loopback с раннером нет.
              def net = "shapoclyack-ci-${CI_SLUG}-${PY}"
              sh "docker network create ${net}"
              try {
                docker.image('postgres:16-alpine').withRun(
                  "--network ${net} --network-alias pg " +
                  "-e POSTGRES_DB=shapoclyack -e POSTGRES_USER=octo -e POSTGRES_PASSWORD=octo-ci-secret"
                ) { pg ->
                  // NATS требует CMD-аргументов (--jetstream и т.д.) — ровно та
                  // причина, по которой в GHA это был ручной docker run.
                  docker.image('nats:2.10.24-alpine').withRun(
                    "--network ${net} --network-alias nats",
                    "--jetstream --store_dir=/data --http_port=8222"
                  ) { nats ->
                    docker.image("python:${PY}-slim").inside("--network ${net} ${PIP_CACHE}") {
                      withEnv([
                        'OCTO_POSTGRES_URL=postgresql+psycopg://octo:octo-ci-secret@pg:5432/shapoclyack',
                        'OCTO_NATS_URL=nats://nats:4222',
                        // Стримы этого брокера живут минуты и на слое
                        // контейнера, без тома. Продовые дефолты (10 ГБ для
                        // INGEST, 1 ГБ для EVENTS) JetStream резервирует
                        // заранее и отвечает 'insufficient storage resources
                        // available', когда на хосте столько не осталось, —
                        // отчего падал не тот тест, который что-то проверяет.
                        'OCTO_NATS_INGEST_MAX_BYTES=268435456',
                        'OCTO_NATS_EVENTS_MAX_BYTES=134217728',
                      ]) {
                        sh '''
                          set -eu
                          # Без apt намеренно: psycopg[binary] везёт libpq в
                          # колесе, компилятор не нужен, а ожидание сервисов
                          # сделано на stdlib. Раньше тут стоял apt-get, и
                          # матрица падала, когда deb.debian.org не ответил.
                          pip install --quiet -r requirements-dev.txt

                          python -m compileall scanner api tests agent

                          echo "[ci] waiting for postgres and jetstream"
                          for i in $(seq 1 60); do
                            python -c "import socket;socket.create_connection(('pg',5432),1)" 2>/dev/null && break
                            sleep 1
                          done
                          for i in $(seq 1 60); do
                            python -c "import urllib.request;urllib.request.urlopen('http://nats:8222/healthz',timeout=1)" 2>/dev/null && break
                            sleep 1
                          done

                          alembic -c api/db/alembic.ini upgrade head

                          python -m pytest -q \
                            --junitxml=junit-''' + PY + '''.xml \
                            --cov=api --cov=scanner \
                            --cov-report=xml:coverage-''' + PY + '''.xml \
                            --cov-report=term-missing \
                            --cov-fail-under=74
                        '''
                      }
                    }
                  }
                }
              } finally {
                sh "docker network rm ${net} || true"
              }
            } finally {
              // В finally, а не после цикла: падение на 3.11 не должно съедать
              // отчёт, который уже написан.
              junit allowEmptyResults: true, testResults: "junit-${PY}.xml"
              archiveArtifacts artifacts: "coverage-${PY}.xml", allowEmptyArchive: true
            }
          }
        }
      }
    }

    stage('Web dashboard') {
      agent { docker { image 'node:26-bookworm-slim'; args '-v shapoclyack-npm-cache:/root/.npm'; reuseNode true } }
      steps {
        // npm ci must not unpack node_modules into the workspace: on macOS that
        // is a VirtioFS bind mount, which drops writes silently. Build #25 died
        // in eslint on a 60 KB run of NUL bytes inside
        // node_modules/language-subtag-registry/data/json/registry.json — the
        // hole was page-aligned and the file kept its correct size, so npm saw
        // nothing to report. #24 had passed on that same revision, which is how
        // the same commit produced both a green and a red build.
        //
        // Building on the container's own filesystem avoids the mount entirely.
        // A named volume over node_modules would too, but it has to be pinned to
        // the workspace path, and parallel stages get their own (shapoclyack@2)
        // — two concurrent builds would then share one node_modules.
        //
        // Nothing downstream consumes web-next/out from the workspace: both
        // Dockerfile.allinone and Dockerfile.api run their own npm ci in a
        // web-build stage. This stage is a gate, not a producer.
        sh '''
          set -eu
          BUILD_DIR=/tmp/web-next-build
          rm -rf "$BUILD_DIR"
          mkdir -p "$BUILD_DIR"
          cp -R web-next/. "$BUILD_DIR/"
          rm -rf "$BUILD_DIR/node_modules" "$BUILD_DIR/.next"
          cd "$BUILD_DIR"
          npm ci
          npm run lint
          npm run typecheck
          npm test
          npm run build
        '''
      }
    }

    stage('SSH deploy (live sshd)') {
      // tests/test_ssh_deploy_live.py: the deployer's argv handed to a real
      // OpenSSH client against a real sshd. Every other test of
      // agent_deployer.py stubs `ssh`, which is how #272 (an argv the client
      // read as options) lived on main unnoticed. Locally the same thing is
      // tests/e2e/ssh-deploy.sh; here the container is orchestrated from
      // Groovy because a port published on the host's loopback is not
      // reachable from this agent.
      //
      // apt is deliberate and retried: python:3.12-slim has no ssh client,
      // and the client under test has to be the one Debian ships in the api
      // and aio images, not a stub. Three attempts before a deb.debian.org
      // hiccup fails the stage.
      agent any
      steps {
        script {
          def net = "shapoclyack-ssh-${CI_SLUG}"
          sh "docker network create ${net}"
          try {
            docker.image('lscr.io/linuxserver/openssh-server@sha256:2a48f9ce01f61c1d7b376b7be99bd12801a3ecd9f339a4c7e7698d529e8d0b47').withRun(
              "--network ${net} --network-alias sshd " +
              "-e PASSWORD_ACCESS=true -e USER_NAME=deploy -e USER_PASSWORD=deploy-ci-secret -e PUID=1000 -e PGID=1000"
            ) { sshd ->
              def fingerprint = ''
              for (int i = 0; i < 60 && !fingerprint; i++) {
                fingerprint = sh(
                  script: "docker exec ${sshd.id} ssh-keygen -lf /config/ssh_host_keys/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print \$2}' || true",
                  returnStdout: true
                ).trim()
                if (!fingerprint) { sleep 1 }
              }
              if (!fingerprint) { error 'sshd never wrote its host key' }
              docker.image('python:3.12-slim').inside("--network ${net} ${PIP_CACHE}") {
                withEnv([
                  'OCTO_SSHD_TEST_HOST=sshd',
                  'OCTO_SSHD_TEST_PORT=2222',
                  'OCTO_SSHD_TEST_USER=deploy',
                  'OCTO_SSHD_TEST_PASSWORD=deploy-ci-secret',
                  "OCTO_SSHD_TEST_FINGERPRINT=${fingerprint}",
                ]) {
                  sh '''
                    set -eu
                    for i in 1 2 3; do
                      apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-client && break
                      echo "[ci] apt attempt $i failed; retrying"; sleep 10
                    done
                    ssh -V
                    pip install --quiet -r requirements-dev.txt
                    for i in $(seq 1 60); do
                      python -c "import socket;socket.create_connection(('sshd',2222),1)" 2>/dev/null && break
                      sleep 1
                    done
                    python -m pytest -q tests/test_ssh_deploy_live.py --junitxml=junit-ssh-live.xml
                  '''
                }
              }
            }
          } finally {
            sh "docker network rm ${net} || true"
            junit allowEmptyResults: true, testResults: 'junit-ssh-live.xml'
          }
        }
      }
    }

    stage('Kustomize') {
      agent any
      steps {
        // kubectl стоит в самом образе Jenkins (см. jenkins-local/Dockerfile).
        // Контейнером тут не обойтись: bitnami/kubectl из Docker Hub выпилен
        // ("not found" на 1.31), а registry.k8s.io/kubectl — distroless, в нём
        // нет bash для запуска скрипта.
        sh 'k8s/scripts/validate-kustomize.sh'
        sh 'k8s/scripts/validate-prometheus-rules.sh'
      }
    }

    stage('Image') {
      agent any
      stages {
        stage('Build (INSTALL_NMAP=0)') {
          steps {
            // GENDEC_READ_TOKEN — приватные релизы GenDec для стадии Pulse.
            // Credential опционален: без него сборка идёт по анонимному пути.
            withCredentials([string(credentialsId: 'GENDEC_READ_TOKEN', variable: 'GH_TOKEN')]) {
              sh """
                set -eu
                DOCKER_BUILDKIT=1 docker build \
                  --secret id=github_token,env=GH_TOKEN \
                  --build-arg INSTALL_NMAP=0 \
                  -t ${IMAGE_TAG} .
              """
            }
          }
        }

        stage('Smoke') {
          steps {
            sh """
              docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint sh ${IMAGE_TAG} -c '
                set -e
                naabu -version
                dnsx -version
                pulse --version
                ! command -v nmap
                python -m compileall scanner
              '
            """
          }
        }

        stage('E2E') {
          steps {
            // TMPDIR обязателен. run.sh делает mktemp -d и монтирует этот путь
            // в docker run, но demon — хостовый: каталог из /tmp контейнера
            // Jenkins на хосте не существует, Docker молча создаёт пустой, и
            // скан падает с FileNotFoundError на scanner/config/default.yaml.
            // Воркспейс смонтирован по одинаковому пути внутри и снаружи,
            // поэтому mktemp внутри него виден обеим сторонам.
            sh """
              set -eu
              mkdir -p "\$WORKSPACE/.e2e-tmp"
              TMPDIR="\$WORKSPACE/.e2e-tmp" bash tests/e2e/run.sh ${IMAGE_TAG}
            """
          }
          post {
            always { sh 'rm -rf "$WORKSPACE/.e2e-tmp" || true' }
          }
        }

        stage('Trivy') {
          steps {
            // Кэш — на джобу, а не общий том `trivy-db` на всех. Trivy берёт
            // на своём кэше блокировку, поэтому две сборки разных веток
            // одновременно роняли друг друга с "Failed to acquire cache or
            // database lock" — тот же класс, что общий тег образа: ресурс один,
            // а джоб теперь много. Воркспейс уже свой у каждой джобы, так что
            // кэш переиспользуется между сборками одной ветки и ни с кем не
            // делится. Цена — первая сборка новой ветки скачивает базу заново.
            sh """
              set -eu
              mkdir -p "\$WORKSPACE/.trivy-cache"

              # Отчёт — не блокирующий
              docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                -v "\$WORKSPACE/.trivy-cache":/root/.cache/trivy aquasec/trivy:latest image \
                --format table --severity CRITICAL,HIGH,MEDIUM --exit-code 0 ${IMAGE_TAG}

              # Гейт — падаем на исправимых CRITICAL
              docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                -v "\$WORKSPACE/.trivy-cache":/root/.cache/trivy \
                -v "\$WORKSPACE/.trivyignore":/.trivyignore \
                aquasec/trivy:latest image \
                --format table --severity CRITICAL --ignore-unfixed \
                --ignorefile /.trivyignore --exit-code 1 ${IMAGE_TAG}
            """
          }
        }

        stage('SBOM') {
          steps {
            sh """
              set -eu
              docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                -v "\$WORKSPACE":/w -w /w anchore/syft:latest \
                ${IMAGE_TAG} -o spdx-json=sbom.spdx.json
            """
            archiveArtifacts artifacts: 'sbom.spdx.json', fingerprint: true
          }
        }

        stage('Load test') {
        // Тяжёлый хвост: 16 контейнеров-мишеней и полный прогон сканера,
        // это самая длинная стадия пайплайна. На ветках она не окупается —
        // сборка ветки нужна, чтобы поймать регресс до мержа, а не чтобы
        // перемерить нагрузку. BRANCH_NAME есть только у multibranch-джобы;
        // у одноветочной 'shapoclyack' он null, поэтому там стадия идёт как
        // раньше.
        when {
          anyOf {
            expression { env.BRANCH_NAME == null }
            branch 'main'
          }
        }
          steps {
            // Порт .github/actions/synthetic-load-test с теми же параметрами,
            // что и в ci.yml: 16 хостов, tests/load/config.yaml, без resume.
            // Шаги build/upload-artifact из composite action не нужны — образ
            // уже собран стадией выше, метрики кладём через archiveArtifacts.
            //
            // TMPDIR — по той же причине, что и в E2E: run.sh делает mktemp -d
            // и монтирует этот путь в docker run на хостовый демон.
            // rm -f метрик: воркспейс между билдами не чистится, и упавший
            // прогон архивировал/гейтил load-metrics.json от прошлого билда
            // (см. #26 — зелёные метрики на ABORTED-сборке).
            sh """
              set -eu
              mkdir -p "\$WORKSPACE/.load-tmp"
              rm -f "\$WORKSPACE/load-metrics.json"
              TMPDIR="\$WORKSPACE/.load-tmp" \
              SCAN_TIMEOUT_SEC=2400 \
              MIN_FRACTION=0.95 \
              METRICS_COPY_TO="\$WORKSPACE/load-metrics.json" \
                bash tests/load/run.sh ${IMAGE_TAG} --hosts 16 --config tests/load/config.yaml
            """
            // Гейт: composite action считал passed в job summary, здесь тот же
            // разбор решает судьбу стадии. python3 есть в образе Jenkins.
            sh '''
              set -eu
              python3 - "$WORKSPACE/load-metrics.json" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    sys.exit(f"[load] метрик нет: {path}")

d = json.loads(path.read_text(encoding="utf-8"))
rows = [
    ("targets", d.get("target_count", d.get("host_count"))),
    ("alive hosts", d.get("alive_hosts")),
    ("open :80", d.get("open_port_matches")),
    ("nmap services", d.get("nmap_open_services")),
    ("duration, s", d.get("duration_sec")),
    ("peak RSS, MiB", d.get("peak_rss_mb")),
]
for name, value in rows:
    print(f"  {name:>16}: {value if value is not None else 'n/a'}")

for item in d.get("failures") or []:
    print(f"  FAIL: {item}")

if not d.get("passed"):
    sys.exit("[load] harness сообщил passed=false")
print("[load] passed")
PY
            '''
          }
          post {
            always {
              archiveArtifacts artifacts: 'load-metrics.json', allowEmptyArchive: true
              sh 'rm -rf "$WORKSPACE/.load-tmp" || true'
            }
          }
        }
      }
      post {
        always {
          // Тег уникален на сборку, поэтому образы копились бы на диске —
          // раньше их перезаписывал следующий билд под тем же именем.
          sh "docker rmi -f ${IMAGE_TAG} || true"
        }
      }
    }

    stage('Image nmap-legacy') {
      agent any
      // Второй вариант образа (с Nmap) нужен на релизном пути, а не на
      // каждой ветке: ещё одна полная сборка образа ради проверки, что
      // легаси-тег собирается.
      when {
        anyOf {
          expression { env.BRANCH_NAME == null }
          branch 'main'
        }
      }
      steps {
        // Этот sh — в одинарных кавычках, поэтому ${IMAGE_TAG} раскрывает не
        // Groovy, а шелл: значение приходит через env, иначе тег молча стал бы
        // пустым и docker build собрал бы "-nmap".
        withEnv(["IMAGE_TAG=${IMAGE_TAG}"]) {
        withCredentials([string(credentialsId: 'GENDEC_READ_TOKEN', variable: 'GH_TOKEN')]) {
          sh '''
            set -eu
            DOCKER_BUILDKIT=1 docker build \
              --secret id=github_token,env=GH_TOKEN \
              --build-arg INSTALL_NMAP=1 \
              -t ${IMAGE_TAG}-nmap .

            docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint sh ${IMAGE_TAG}-nmap -c '
              set -e
              naabu -version
              dnsx -version
              pulse --version
              nmap --version | head -n 1
              test -f /usr/share/nmap/scripts/nmap-vulners/vulners.nse
              test -f /usr/share/nmap/scripts/vulscan/vulscan.nse
              python -m compileall scanner
            '
          '''
        }
        }
      }
      post {
        always {
          sh "docker rmi -f ${IMAGE_TAG}-nmap || true"
        }
      }
    }
  }
}
