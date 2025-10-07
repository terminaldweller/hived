.PHONY: test deploy down build help

IMAGE_NAME=hived

test:
	nq docker compose -f ./docker-compose-test.yaml up --build

deploy:
	nq docker compose -f ./docker-compose.yaml up --build

down:
	docker compose -f ./docker-compose.yaml down
	docker compose -f ./docker-compose-test.yaml down

build: d_build_distroless_vendored

build_regular:
	docker build -t $(IMAGE_NAME)-f ./hived/Dockerfile ./hived

build_distroless:
	docker build -t $(IMAGE_NAME) -f ./hived/Dockerfile_distroless ./hived

build_distroless_vendored:
	docker build -t $(IMAGE_NAME) -f ./hived/Dockerfile_distroless_vendored ./hived

help:
	@echo "d_test"
	@echo "d_deploy"
	@echo "d_down"
	@echo "d_build"
