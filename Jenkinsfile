pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh '''#!/bin/bash
                set -e
                # Verify Python installation
                command -v python3.9 >/dev/null 2>&1 || { echo >&2 "Python 3.9 is not installed. Aborting."; exit 1; }
                
                # Create virtual environment if missing
                if [ ! -d "venv" ]; then
                    /usr/bin/env python3.9 -m venv venv
                fi
                
                # Activate the virtual environment and install dependencies
                source venv/bin/activate
                /usr/bin/env pip install --upgrade pip
                /usr/bin/env pip install -r requirements.txt gunicorn pymysql cryptography
                
                export FLASK_APP=microblog.py
                flask db upgrade
                flask translate compile
                '''
            }
        }
        // NOTE: For this workload's purposes, we are not focusing on testing
        // stage('Test') {
        //     steps {
        //         sh '''#!/bin/bash
        //         source venv/bin/activate
        //         export PYTHONPATH=$PYTHONPATH:$(pwd)
        //         export FLASK_APP=microblog.py
        //         pytest --junit-xml=test-reports/results.xml ./tests/unit/ --verbose
        //         '''
        //     }
        //     post {
        //         always {
        //             junit 'test-reports/results.xml'
        //         }
        //     }
        // }
        stage('OWASP FS SCAN') {
            steps {
                dependencyCheck additionalArguments: '--scan ./ --disableYarnAudit --disableNodeAudit', odcInstallation: 'DP-Check'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }
        stage('Clean') {
            steps {
                sh '''#!/bin/bash
                PID=$(pgrep flask)
                if [ -n "$PID" ]; then
                    kill $PID
                    echo "Killed flask process with PID: $PID"
                else
                    echo "No flask process running"
                fi
                '''
            }
        }
        stage('Deploy') {
            steps {
                sh '''#!/bin/bash
                chmod +x blog.sh
                ./blog.sh
                sleep 5
                if pgrep flask > /dev/null; then
                    echo "Application deployed successfully"
                else
                    echo "Deployment failed"
                    exit 1
                fi
                '''
            }
        }
    }
}