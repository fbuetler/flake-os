# Building the Docker Image

## Building the Image

To build the image simply type.

```
make build
```

## Test the Image

The build step will create a new local docker container.
It's good to test the image before pushing it to docker hub.
The variables are set in the make file.

```
make test
```
## Pushblish the Image

First you will need to log in to docker hub:

```
DOCKER_HUB_USER=<USERNAME> make login
```

Then you can publish the image. This adds the tags, and also sets the latest tag.

```
DOCKER_HUB_USER=<USERNAME> make publish
```

## Updating to a new LTS

 1. Change the `FROM` clause in the `Dockerfile`.
 2. Change the image tag in the `Makefile`
 3. Rebuild and publish the image