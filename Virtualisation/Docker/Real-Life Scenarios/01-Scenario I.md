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
