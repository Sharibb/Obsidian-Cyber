### I pulled a docker image of kali made some changes but forgot to add storage volume in docker run command

#### Solution
If you made Changes in the docker just commit the changes to the new docker image using

```bash

docker commit <container_name> my_new_image

```

### A reliable way to create a file sharing point for host and docker container kali
### 1. **Create a Shared Directory on the Host**
```bash
mkdir -p ~/docker_shared  # Create if it doesn't exist
```
### 2. **Copy Existing Files from Container to Host (Temporary Step)**
```bash
docker cp <container_name>:/path/inside/container ~/docker_shared
```
### 3. **Stop and Recreate the Container with Bind Mount**
```shell
# Stop the container
docker stop <container_name>

# Recreate with persistent bind mount
docker run -d --name <new_container_name> \
  -v ~/docker_shared:/path/inside/container \
  [OTHER_OPTIONS] \
  your_image:tag
```
_Example:_
```bash
docker run -d --name my_app_v2 \
  -v ~/docker_shared:/app/data \
  -p 8080:80 \
  my_image:latest
```

### 4. **Verify File Access**

- **Host → Container**:

```bash
echo "Test from host" > ~/docker_shared/host_test.txt
docker exec <container_name> cat /path/inside/container/host_test.txt
```
	
- **Container → Host**:

```bash
docker exec <container_name> sh -c 'echo "Test from container" > /path/inside/container/container_test.txt'
cat ~/docker_shared/container_test.txt
```

