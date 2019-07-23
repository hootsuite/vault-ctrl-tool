# Introduction

At Hootsuite, we have an internal repository that fetches this repository, runs `make build`, then deploys
the generated binary into a number of different forms internally. This document discusses how you can do this too.

# Snippets from the Hootsuite Build

Our Makefile assumes this project is checked out into `target/open-source-project`, and therefore has a
target to trigger a build:

```
jenkins-build:
    make -C target/open-source-project build
    @mkdir -p bin
    cp target/open-source-project/bin/vault-ctrl-tool.* bin/
```

To embed the tool in a Docker container (if you're using it with Kubernetes), you can have a simple
Dockerfile:

```dockerfile
FROM ubuntu:latest
ADD bin/vault-ctrl-tool.linux.amd64 /vault-ctrl-tool
CMD []
```

and then make targets:

```
docker-image:
  docker build -t vault-ctrl-tool:latest .
  
docker-deploy:
	docker tag vault-ctrl-tool:latest docker-registry.hootsuite.com/tools/vault-ctrl-tool:latest
	docker tag vault-ctrl-tool:latest docker-registry.hootsuite.com/tools/vault-ctrl-tool:$(BUILD_ID)
	docker push docker-registry.hootsuite.com/tools/vault-ctrl-tool:latest
	docker push docker-registry.hootsuite.com/tools/vault-ctrl-tool:$(BUILD_ID)
```

Our `Jenkinsfile` works something similar to:

```groovy
node('example') {

    stage('Setup') {
        checkout scm
    }

    stage('Checkout Open Source Project') {
        checkout scm: [
                $class                           : 'GitSCM',
                branches                         : [[name: '*/master']],
                doGenerateSubmoduleConfigurations: false,
                extensions                       : [[$class           : 'RelativeTargetDirectory',
                                                     relativeTargetDir: 'target/open-source-project']],
                submoduleCfg                     : [],
                userRemoteConfigs                : [[url: 'https://github.com/hootsuite/vault-ctrl-tool.git']]
        ]

    }

    stage('Build') {
        sh "make jenkins-build"
    }

    stage('Deploy') {
        sh "make deploy"
    }
}
```

Hope this helps!