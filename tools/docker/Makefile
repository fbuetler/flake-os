# Copyright (c) 2021 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.


# set the docker hub user, should be passed in by the environemnt
DOCKER_HUB_USER?=user-not-set

# set the name for the docker image
IMAGE_NAME=barrelfish-aos

# set the image tag
IMAGE_TAG=20.04-lts


build: Dockerfile install.sh entrypoint.sh
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

publish: build
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_HUB_USER)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_HUB_USER)/$(IMAGE_NAME):latest
	docker push $(DOCKER_HUB_USER)/$(IMAGE_NAME):$(IMAGE_TAG)

test:
	BF_DOCKER=$(IMAGE_NAME):$(IMAGE_TAG) bash test.sh

login:
	docker login $(DOCKER_HUB_USER)
