pipeline {
  agent any
  parameters {
    string(name: 'IMAGE', defaultValue: 'nginx:1.23', description: 'Image to scan')
    choice(name: 'SEVERITY_FAIL_LEVEL', choices: ['LOW','MEDIUM','HIGH','CRITICAL'], description: 'Fail threshold')
    booleanParam(name: 'IGNORE_UNFIXED', defaultValue: true, description: 'Ignore unfixed vulns')
  }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('Install Tools') {
      steps {
        sh '''
          python3 -m pip install -r requirements.txt --quiet
          if ! command -v trivy >/dev/null 2>&1; then
            TRIVY_VER=0.52.0
            wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.deb
            sudo dpkg -i trivy_${TRIVY_VER}_Linux-64bit.deb
          fi
          trivy --version
        '''
      }
    }
    stage('Scan') {
      environment {
        SLACK_WEBHOOK_URL = credentials('slack-webhook-secret-id') // or leave blank
        TEAMS_WEBHOOK_URL = '' // optional
        PUSHGATEWAY_URL = ''   // optional
      }
      steps {
        sh '''
          cp -f config/policy.env.example config/policy.env
          sed -i "s/^SEVERITY_FAIL_LEVEL=.*/SEVERITY_FAIL_LEVEL=${SEVERITY_FAIL_LEVEL}/" config/policy.env
          sed -i "s/^IGNORE_UNFIXED=.*/IGNORE_UNFIXED=${IGNORE_UNFIXED}/" config/policy.env
          ./scripts/scan_image.sh "${IMAGE}"
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'reports/*', fingerprint: true
        }
      }
    }
  }
}

