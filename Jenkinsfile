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
                            apt-get update -qq && apt-get install -y --no-install-recommends gcc libpq-dev curl >/dev/null
                            pip install --quiet -r requirements-dev.txt

                            python -m compileall scanner api tests agent

                            echo "[ci] waiting for postgres and jetstream"
                            for i in $(seq 1 60); do
                              python -c "import socket;socket.create_connection(('pg',5432),1)" 2>/dev/null && break
                              sleep 1
                            done
                            for i in $(seq 1 60); do
                              curl -fsS http://nats:8222/healthz >/dev/null 2>&1 && break
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
        // bitnami/kubectl держит kubectl как entrypoint, поэтому docker.inside()
        // сюда не годится — запускаем скрипт явным docker run с bash.
        sh '''
          set -eu
          docker run --rm -v "$WORKSPACE":/w -w /w --entrypoint bash \
            bitnami/kubectl:1.31 k8s/scripts/validate-kustomize.sh
        '''
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
          steps { sh "bash tests/e2e/run.sh ${IMAGE_TAG}" }
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
          when { expression { return false } }
          steps {
            // .github/actions/synthetic-load-test — composite action, прямого
            // аналога нет. Портировать вызовом tests/load/ напрямую, когда дойдут руки.
            echo 'skipped: synthetic-load-test не портирован'
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
