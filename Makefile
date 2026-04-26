IMAGE_REGISTRY ?= reg.mkrcc.com
IMAGE_NAMESPACE ?= pushforge
IMAGE_NAME ?= pushforge
IMAGE_REPO ?= $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_NAME)
VERSION ?= $(shell git describe --tags --always --dirty)
IMAGE_TAG ?= $(VERSION)
PLATFORMS ?= linux/amd64,linux/arm64
BUILDER_NAME ?= pushforge-builder

OCI_ARTIFACT_REPO ?= $(IMAGE_REPO)-artifact
OCI_ARTIFACT_REF ?= $(OCI_ARTIFACT_REPO):$(IMAGE_TAG)
OCI_ARTIFACT_MEDIA_TYPE ?= application/vnd.pushforge.source.v1.tar+gzip
COMPOSE_ARTIFACT_REPO ?= $(IMAGE_REPO)-compose
COMPOSE_ARTIFACT_REF ?= $(COMPOSE_ARTIFACT_REPO):$(IMAGE_TAG)
COMPOSE_FILE_OCI ?= compose.oci.yaml
COMPOSE_IMAGE_FILE ?= $(ARTIFACT_DIR)/compose.oci.image.yaml
COMPOSE_RENDERED_FILE ?= $(ARTIFACT_DIR)/compose.oci.with-env.yaml

ARTIFACT_DIR ?= dist
ARTIFACT_NAME ?= pushforge-$(IMAGE_TAG).tar.gz
ARTIFACT_PATH ?= $(ARTIFACT_DIR)/$(ARTIFACT_NAME)

.PHONY: help test compose-config builder-create image-build image-push image-push-multi artifact-pack artifact-push compose-render compose-publish compose-publish-with-env release release-multi clean

help:
	@echo "PushForge release targets"
	@echo "  make test             Run Python tests"
	@echo "  make compose-config   Validate merged production Compose config"
	@echo "  make image-build      Build local Docker image"
	@echo "  make image-push       Build and push image for the current Docker architecture"
	@echo "  make image-push-multi Build and push multi-platform image"
	@echo "  make artifact-pack    Create OCI artifact payload tarball"
	@echo "  make artifact-push    Push source bundle OCI artifact with ORAS"
	@echo "  make compose-render   Render Compose OCI file with the release image"
	@echo "  make compose-publish  Push Docker Compose project OCI artifact without local .env values"
	@echo "  make compose-publish-with-env Push Docker Compose OCI artifact with local .env values"
	@echo "  make release          Push current-architecture image and OCI artifacts"
	@echo "  make release-multi    Push multi-platform image and OCI artifacts"
	@echo "  make builder-create   Create a buildx docker-container builder for multi-platform builds"
	@echo ""
	@echo "Common overrides:"
	@echo "  IMAGE_REGISTRY=reg.mkrcc.com IMAGE_NAMESPACE=library IMAGE_NAME=pushforge VERSION=v1.0.0"

test:
	python -m unittest discover -s tests

compose-config:
	docker compose -f compose.yaml -f compose.prod.yaml config

builder-create:
	docker buildx create --name $(BUILDER_NAME) --driver docker-container --use --bootstrap

image-build:
	docker buildx build --load -t $(IMAGE_REPO):$(IMAGE_TAG) .

image-push:
	docker buildx build --push -t $(IMAGE_REPO):$(IMAGE_TAG) -t $(IMAGE_REPO):latest .

image-push-multi:
	docker buildx build --push --platform $(PLATFORMS) -t $(IMAGE_REPO):$(IMAGE_TAG) -t $(IMAGE_REPO):latest .

artifact-pack:
	mkdir -p $(ARTIFACT_DIR)
	tar \
		--exclude=.git \
		--exclude=.venv \
		--exclude=.tmp-tests \
		--exclude=.env \
		--exclude=__pycache__ \
		--exclude=logs \
		--exclude=dist \
		-czf $(ARTIFACT_PATH) .

artifact-push: artifact-pack
	oras push $(OCI_ARTIFACT_REF) \
		$(ARTIFACT_PATH):$(OCI_ARTIFACT_MEDIA_TYPE) \
		--annotation org.opencontainers.image.title=PushForge \
		--annotation org.opencontainers.image.description="PushForge source and deployment bundle" \
		--annotation org.opencontainers.image.version=$(IMAGE_TAG)

compose-render:
	mkdir -p $(ARTIFACT_DIR)
	PUSHFORGE_IMAGE=$(IMAGE_REPO):$(IMAGE_TAG) docker compose -f $(COMPOSE_FILE_OCI) config > $(COMPOSE_RENDERED_FILE)

compose-publish:
	mkdir -p $(ARTIFACT_DIR)
	cp $(COMPOSE_FILE_OCI) $(COMPOSE_IMAGE_FILE)
	sed -i.bak 's|image: $${PUSHFORGE_IMAGE:-reg.mkrcc.com/library/pushforge:latest}|image: $(IMAGE_REPO):$(IMAGE_TAG)|' $(COMPOSE_IMAGE_FILE)
	rm -f $(COMPOSE_IMAGE_FILE).bak
	docker compose -f $(COMPOSE_IMAGE_FILE) publish -y $(COMPOSE_ARTIFACT_REF)

compose-publish-with-env: compose-render
	docker compose -f $(COMPOSE_RENDERED_FILE) publish -y $(COMPOSE_ARTIFACT_REF)

release: image-push compose-publish artifact-push

release-multi: image-push-multi compose-publish artifact-push

clean:
	rm -rf $(ARTIFACT_DIR)
