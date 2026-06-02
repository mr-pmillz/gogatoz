package pipeline

import (
	"strings"
	"testing"
)

const benchParseYAML = `
stages: [build, test, deploy, security]
variables:
  DOCKER_HOST: tcp://docker:2375
  REGISTRY: registry.example.com
  APP_NAME: myapp

include:
  - local: ".gitlab/ci/security.yml"
  - project: "devops/ci-templates"
    file: ["/templates/docker.yml"]
    ref: "v2.1.0"
  - remote: "https://example.com/shared-ci.yml"
  - template: "Security/SAST.gitlab-ci.yml"

workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      when: always
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      when: always

default:
  image: alpine:3.19
  tags: [docker]

.base_job: &base
  before_script:
    - echo "Setting up..."

.deploy_base:
  tags: [self-hosted, production]
  variables:
    DEPLOY_ENV: staging
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      when: on_success

build:
  stage: build
  <<: *base
  image: docker:24.0
  services:
    - docker:24.0-dind
  script:
    - docker build -t $REGISTRY/$APP_NAME:$CI_COMMIT_SHA .
  artifacts:
    paths: [dist/]
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

unit_test:
  stage: test
  <<: *base
  image: golang:1.22
  script:
    - go test -race ./...
  needs: [build]

integration_test:
  stage: test
  extends: .base_job
  image: golang:1.22
  script:
    - make integration-test COMMIT_MSG=$CI_COMMIT_MESSAGE
  services:
    - name: postgres:16
      alias: db
  needs: [build]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

sast_scan:
  stage: security
  script:
    - curl https://scanner.example.com/run.sh | bash
  allow_failure: true

deploy_staging:
  stage: deploy
  extends: .deploy_base
  environment: staging
  script:
    - kubectl apply -f k8s/
  needs: [unit_test, integration_test]

deploy_production:
  stage: deploy
  extends: .deploy_base
  environment: production
  tags: [self-hosted, production]
  when: manual
  needs: [deploy_staging]
  variables:
    DEPLOY_ENV: production
`

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		doc, err := Parse(strings.NewReader(benchParseYAML))
		if err != nil {
			b.Fatal(err)
		}
		if len(doc.Jobs) == 0 {
			b.Fatal("expected jobs")
		}
	}
}
