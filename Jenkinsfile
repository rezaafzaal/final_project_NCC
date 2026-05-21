pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    triggers {
        githubPush()
    }

    environment {
        IMAGE_NAME = 'siem-dashboard'
        SONARQUBE_ENV = 'sonarserver'
        SCANNER_HOME = tool 'sonarqube8.0'
        PIP_CACHE_DIR = "${WORKSPACE}/.pip-cache"
        HOST_WORKSPACE = "/var/lib/docker/volumes/jenkins-data/_data/workspace/${JOB_NAME}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Debug Workspace') {
            steps {
                sh '''
                    pwd
                    ls -la
                    ls -la backend || true
                    find . -maxdepth 2 -type f | sort
                '''
            }
        }

        stage('Setup') {
            steps {
                sh '''
                    git config --global --add safe.directory ${WORKSPACE}
                    docker version
                '''
            }
        }

        stage('Install & Test') {
            steps {
                sh '''
                    docker run --rm \
                      --user root \
                      -e HOME=/tmp \
                      -e PIP_CACHE_DIR=/tmp/pip-cache \
                      -e XDG_CACHE_HOME=/tmp/.cache \
                      -v "$HOST_WORKSPACE":/workspace \
                      -w /workspace \
                      python:3.11-slim \
                      sh -lc "mkdir -p /tmp/pip-cache /tmp/.cache && \
                             python -m pip install -r backend/requirements.txt && \
                             python -m pip install pytest pytest-asyncio httpx && \
                             python -m pytest backend/tests/ -v --tb=short || true"
                '''
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv("${SONARQUBE_ENV}") {
                    sh """
                        ${SCANNER_HOME}/bin/sonar-scanner
                        test -f "\$WORKSPACE/.scannerwork/report-task.txt"
                    """
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 20, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} ."
                sh "docker tag ${IMAGE_NAME}:${BUILD_NUMBER} ${IMAGE_NAME}:latest"
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    docker-compose down || true
                    docker-compose up -d
                '''
            }
        }
    }

    post {
        success {
            echo 'Pipeline sukses'
        }
        failure {
            echo 'Pipeline gagal'
        }
    }
}
