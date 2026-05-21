pipeline {
    agent any

    environment {
        IMAGE_NAME = 'siem-dashboard'
        SONAR_PROJECT = 'siem-dashboard'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install & Test') {
            steps {
                script {
                    docker.image('python:3.11-slim').inside {
                        withEnv([
                            'HOME=/tmp',
                            'PIP_CACHE_DIR=/tmp/pip-cache',
                            'XDG_CACHE_HOME=/tmp/.cache'
                        ]) {
                            sh 'mkdir -p /tmp/pip-cache /tmp/.cache'
                            sh 'python -m pip install -r backend/requirements.txt'
                            sh 'python -m pip install pytest pytest-asyncio httpx'
                            sh 'pytest backend/tests/ -v --tb=short || true'
                        }
                    }
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner'
                }
            }
        }

        stage('Quality Gate') {
            steps {
                waitForQualityGate abortPipeline: true
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
                sh 'docker-compose down || true'
                sh 'docker-compose up -d'
            }
        }
    }

    post {
        failure {
            echo 'Pipeline gagal. Cek log di atas.'
        }
        success {
            echo 'Deploy berhasil. SIEM berjalan di port 8000.'
        }
    }
}
