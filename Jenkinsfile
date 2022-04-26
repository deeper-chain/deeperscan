#!groovy

def slackChannel = '#deeper-chain-devops'
def execNode = 'master-runner'
def upstreamProjects = ''
def timeStamp = Calendar.getInstance().getTime().format('YYYYMMdd')

def deployCmd = 'kubectl set image deployment/deeper-scan   -n dev explorer-api=561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-api:$TAG \
harvester-api=561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-harvester:$TAG \
harvester-worker=561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-harvester:$TAG \
harvester-beat=561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-harvester:$TAG \
harvester-monitor=561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-harvester:$TAG \
explorer-gui=561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-gui:dev-$TAG '
if (env.BRANCH_NAME == "master") {
    deployCmd = ""
}


pipeline {
    agent {
        node { label execNode }
    }

    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '5', artifactNumToKeepStr: '3'))
    }

    triggers {
        upstream(
            upstreamProjects: upstreamProjects,
            threshold: hudson.model.Result.SUCCESS
        )
    }
    environment {
        webhook_key = credentials('webhook_key')
        TAG = "${timeStamp}"
        DEPLOYCMD = "${deployCmd}"
    }

    stages {
        stage('test') {
            when {
                not {
                    anyOf {
                        branch 'master'
                    }
                }
            }
            stages {
                stage('Unit Test') {
                    steps {
                        echo 'prepare to code test'
                    //TODO
                    }
                }
                stage('report') {
                    when {
                        not {
                            branch 'PR-*'
                        }
                    }
                    steps {
                        echo 'generate code report'
                    //TODO
                    }
                }
            }
        }

        stage('Build') {
            when {
                anyOf {
                   branch env.BRANCH_NAME
                }
            }
            steps {    
            dir("explorer-api"){
                sh 'echo $TAG ...........'
                sh 'docker build -t 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-api:$TAG .'
            }
            dir("harvester"){
                sh 'docker build -t 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-harvester:$TAG .'
            }
            dir("explorer-gui"){
                sh 'docker build --build-arg API_URL=https://dev.deeperscan.io/api/v1 --build-arg NETWORK_NAME=Deeper --build-arg NETWORK_ID=deeper --build-arg NETWORK_TYPE=pre --build-arg CHAIN_TYPE=relay --build-arg NETWORK_TOKEN_SYMBOL=DPR --build-arg NETWORK_TOKEN_DECIMALS=18 --build-arg NETWORK_COLOR_CODE=21C355 -t 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-gui:dev-$TAG .'
                sh 'docker build --build-arg API_URL=https://scan.deeper.network/api/v1  --build-arg NETWORK_NAME=Deeper --build-arg NETWORK_ID=deeper --build-arg NETWORK_TYPE=pre --build-arg CHAIN_TYPE=relay --build-arg NETWORK_TOKEN_SYMBOL=DPR --build-arg NETWORK_TOKEN_DECIMALS=18 --build-arg NETWORK_COLOR_CODE=21C355 -t 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-gui:prod-$TAG .'
            }
            }
        }
        stage('Push Image'){
            when {
                anyOf{
                    branch env.BRANCH_NAME
                }
            }
            steps{
                sh '''
                docker push 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-api:$TAG
                docker push 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-harvester:$TAG
                docker push 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-gui:dev-$TAG
                docker push 561108432312.dkr.ecr.ap-southeast-1.amazonaws.com/deeperscan/pre-explorer-gui:prod-$TAG
                '''
            }
        }

        stage('Deploy Code') {
            when {
                anyOf {
                    branch env.BRANCH_NAME
                }
            }
            steps {
                sh '$DEPLOYCMD'
            }
        }
    }
    post {
        success {
            slackSend channel: slackChannel, color: 'good',
                message: "${env.JOB_NAME} CICD SUCCESS,<${env.BUILD_URL}console|cliek me get details>"
        }
        failure {
            slackSend channel: slackChannel, color: 'danger',
                message: "${env.JOB_NAME} CICD FAILED!!! <${env.BUILD_URL}console|cliek me check log>"
        }
    }

}