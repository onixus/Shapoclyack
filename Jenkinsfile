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
def IMAGE_TAG = 'network-scan-cli:ci'

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
      matrix {
        axes {
          axis { name 'PY'; values '3.11', '3.12' }
        }
        agent any
        stages {
          stage('pytest') {
            steps {
              script {
                // Своя сеть на сборку: postgres и nats резолвятся по alias'ам.
                // 127.0.0.1 из GitHub Actions тут не работает — у каждого
                // контейнера свой netns, общего loopback с раннером нет.
                def net = "shapoclyack-ci-${env.BUILD_NUMBER}-${PY}"
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
              }
            }
            post {
              always {
                junit allowEmptyResults: true, testResults: "junit-${PY}.xml"
                archiveArtifacts artifacts: "coverage-${PY}.xml", allowEmptyArchive: true
              }
            }
          }
        }
      }
    }

    stage('Web dashboard') {
      agent { docker { image 'node:26-bookworm-slim'; args '-v shapoclyack-npm-cache:/root/.npm'; reuseNode true } }
      steps {
        dir('web-next') {
          sh '''
            set -eu
            npm ci
            npm run lint
            npm run typecheck
            npm test
            npm run build
          '''
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
            sh """
              set -eu
              # Отчёт — не блокирующий
              docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                -v trivy-db:/root/.cache/trivy aquasec/trivy:latest image \
                --format table --severity CRITICAL,HIGH,MEDIUM --exit-code 0 ${IMAGE_TAG}

              # Гейт — падаем на исправимых CRITICAL
              docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                -v trivy-db:/root/.cache/trivy -v "\$WORKSPACE/.trivyignore":/.trivyignore \
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
          steps {
            // Порт .github/actions/synthetic-load-test с теми же параметрами,
            // что и в ci.yml: 16 хостов, tests/load/config.yaml, без resume.
            // Шаги build/upload-artifact из composite action не нужны — образ
            // уже собран стадией выше, метрики кладём через archiveArtifacts.
            //
            // TMPDIR — по той же причине, что и в E2E: run.sh делает mktemp -d
            // и монтирует этот путь в docker run на хостовый демон.
            sh """
              set -eu
              mkdir -p "\$WORKSPACE/.load-tmp"
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
    }

    stage('Image nmap-legacy') {
      agent any
      steps {
        withCredentials([string(credentialsId: 'GENDEC_READ_TOKEN', variable: 'GH_TOKEN')]) {
          sh '''
            set -eu
            DOCKER_BUILDKIT=1 docker build \
              --secret id=github_token,env=GH_TOKEN \
              --build-arg INSTALL_NMAP=1 \
              -t network-scan-cli:ci-nmap .

            docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint sh network-scan-cli:ci-nmap -c '
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
  }
}
