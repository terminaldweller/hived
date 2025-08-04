.PHONY: d_test d_deploy d_down d_build help

IMAGE_NAME=hived

d_test:
	nq docker compose -f ./docker-compose-test.yaml up --build

d_deploy:
	nq docker compose -f ./docker-compose.yaml up --build

d_down:
	docker compose -f ./docker-compose.yaml down
	docker compose -f ./docker-compose-test.yaml down

d_build: d_build_distroless_vendored

d_build_regular:
	docker build -t $(IMAGE_NAME)-f ./hived/Dockerfile ./hived

d_build_distroless:
	docker build -t $(IMAGE_NAME) -f ./hived/Dockerfile_distroless ./hived

d_build_distroless_vendored:
	docker build -t $(IMAGE_NAME) -f ./hived/Dockerfile_distroless_vendored ./hived

help:
	@echo "d_test"
	@echo "d_deploy"
	@echo "d_down"
	@echo "d_build"
