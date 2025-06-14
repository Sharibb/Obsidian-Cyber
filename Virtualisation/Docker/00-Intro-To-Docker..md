give a brief explation about docker it uses and leave spaces for images


# Introduction to Docker  

## What is Docker?  

Docker is an open-source platform that enables developers to **build, deploy, and run applications in lightweight, portable containers**. Containers package an application with all its dependencies (libraries, frameworks, runtime) into a single unit, ensuring consistency across different environments.  

### Key Benefits of Docker:  
✔ **Portability** – Run the same container on any OS or cloud platform.  
✔ **Isolation** – Containers run independently without interfering with each other.  
✔ **Efficiency** – Lightweight compared to virtual machines (VMs).  
✔ **Scalability** – Easily scale applications using orchestration tools like Kubernetes.  

---

## How Docker Works  

Docker uses a **client-server architecture**:  
- The **Docker Client** (CLI) sends commands to the **Docker Daemon**, which builds and runs containers.  
- Images are stored in a **registry** (e.g., Docker Hub).  

![[docker-01.png]]

---

## Common Use Cases  

🚀 **Microservices Architecture** – Deploy services independently in containers.  
🔧 **CI/CD Pipelines** – Ensure consistent testing & deployment environments.  
📦 **Legacy App Modernization** – Containerize old apps for easier management.  
🛠️ **Development Environments** – Avoid "works on my machine" issues.  

![[docker-02.png]]

---

## Basic Docker Commands  

| Command | Description |  
|---------|------------|  
| `docker run` | Starts a container from an image |  
| `docker build` | Creates an image from a Dockerfile |  
| `docker ps` | Lists running containers |  
| `docker pull` | Downloads an image from a registry |  


---

### **Docker Basic Commands Cheat Sheet**

#### **Container Management**
| Command | Description |
|---------|-------------|
| `docker run [OPTIONS] IMAGE [CMD]` | Create and start a container from an image. |
| `docker start CONTAINER` | Start a stopped container. |
| `docker stop CONTAINER` | Stop a running container gracefully. |
| `docker restart CONTAINER` | Restart a container. |
| `docker pause CONTAINER` | Pause all processes in a container. |
| `docker unpause CONTAINER` | Unpause a paused container. |
| `docker kill CONTAINER` | Force-stop a container (SIGKILL). |
| `docker rm CONTAINER` | Remove one or more stopped containers. |
| `docker rm -f CONTAINER` | Force-remove a running container. |
| `docker ps` | List running containers. |
| `docker ps -a` | List all containers (including stopped ones). |
| `docker logs CONTAINER` | Fetch logs of a container. |
| `docker logs -f CONTAINER` | Follow logs in real-time (`--follow`). |
| `docker exec -it CONTAINER CMD` | Run a command inside a running container interactively (`-it = interactive TTY`). |

#### **Image Management**
| Command                                | Description                                      |
| -------------------------------------- | ------------------------------------------------ |
| `docker images`                        | List all local images.                           |
| `docker pull IMAGE[:TAG]`              | Download an image from Docker Hub/registry.      |
| `docker push IMAGE[:TAG]`              | Upload an image to Docker Hub/registry.          |
| `docker rmi IMAGE`                     | Remove one or more local images.                 |
| `docker rmi -f IMAGE`                  | Force-remove an image (even if in use).          |
| `docker build -t TAG PATH`             | Build an image from a Dockerfile (`-t` for tag). |
| `docker history IMAGE`                 | Show layers and build history of an image.       |
| `docker tag SOURCE_IMAGE TARGET_IMAGE` | Tag an image for versioning or registry push.    |


#### **Network Management**  
| Command | Description |  
|---------|-------------|  
| `docker network ls` | List all networks. |  
| `docker network inspect NETWORK` | Show detailed network info. |  
| `docker network create NETWORK` | Create a new network. |  
| `docker network connect NETWORK CONTAINER` | Connect a container to a network. |  

#### **Volume Management**  
| Command | Description |  
|---------|-------------|  
| `docker volume ls` | List all volumes. |  
| `docker volume create VOLUME_NAME` | Create a new volume. |  
| `docker volume inspect VOLUME_NAME` | Show volume details. |  

#### **System & Cleanup**  
| Command                             | Description                                         |
| ----------------------------------- | --------------------------------------------------- |
| `docker system df`                  | Show disk usage (images, containers, volumes).      |
| `docker prune [TYPE]`               | Remove unused objects (`--all`, `--volumes`, etc.). |
| `docker stats CONTAINER`            | Live resource usage stats for containers.           |
| `docker info`                       | Display system-wide Docker information.             |
| `docker version`                    | Show Docker client and server versions.             |
| `docker events`                     | Stream real-time Docker events.                     |
| `docker update CONTAINER [OPTIONS]` | Update container resource limits (CPU/memory).      |

#### **Docker Compose Basics**  
| Command | Description |  
|---------|-------------|
| `docker-compose up` | Create and start containers from `docker-compose.yml`. |
| `docker-compose up -d` | Run in detached mode (background). |
| `docker-compose down` | Stop and remove containers, networks, volumes. |
| `docker-compose logs` | View output from all services. |

#### **Registry & Login**  
| Command | Description |  
|---------|-------------|
| `docker login [SERVER]` | Log in to a registry (default: Docker Hub). |
| `docker logout [SERVER]` | Log out from a registry. |
| `docker search TERM` | Search Docker Hub for images. |

#### **Advanced Operations**  
| Command                                  | Description                                                           |
| ---------------------------------------- | --------------------------------------------------------------------- |
| `docker save IMAGE > file.tar`           | Save an image to a tar archive.                                       |
| `docker load < file.tar`                 | Load an image from a tar archive.                                     |
| `docker inspect OBJECT`                  | Show low-level details of any Docker object (container/image/volume). |
| `docker diff CONTAINER`                  | Show filesystem changes in a container (added/modified/deleted).      |
| `docker commit CONTAINER [IMAGE]`        | Create an image from a container's changes.                           |
| `docker cp CONTAINER:SRC_PATH DEST_PATH` | Copy files between container and host.                                |
| `docker export CONTAINER > file.tar`     | Export container filesystem as tar archive.                           |
| `docker import file.tar [IMAGE]`         | Create image from tarball (opposite of export).                       |


#### **Swarm Mode (Basic)**  
| Command                                   | Description                     |
| ----------------------------------------- | ------------------------------- |
| `docker swarm init`                       | Initialize a Swarm cluster.     |
| `docker swarm join-token WORKER/MANAGER`  | Get join tokens for nodes.      |
| `docker node ls`                          | List nodes in the Swarm.        |
| `docker service create --name NAME IMAGE` | Deploy a service in Swarm mode. |


#### **Debugging & Troubleshooting**  
| Command                   | Description                                   |
| ------------------------- | --------------------------------------------- |
| `docker top CONTAINER`    | Display running processes in a container.     |
| `docker port CONTAINER`   | List port mappings for a container.           |
| `docker attach CONTAINER` | Attach to a running container's STDIN/STDOUT. |

#### **Security & Context**  
| Command                        | Description                                                |
| ------------------------------ | ---------------------------------------------------------- |
| `docker scan IMAGE`            | Scan an image for vulnerabilities (requires Docker Scout). |
| `docker context ls/use/create` | Manage Docker contexts (multi-environment switching).      |

#### **Shortcuts & Tips**  
- Use tab completion for image/container names  
- Chain commands with `&&`:  
  ```sh
  docker stop my_container && docker rm my_container
  ```
- Use JSON formatting with inspect:  
  ```sh
  docker inspect --format='{{json .State}}' CONTAINER
  ```


- Use `--rm` flag with `docker run` for automatic container cleanup:  
  ```sh
  docker run --rm -it ubuntu bash
  ```
- Quickly remove all stopped containers:  
  ```sh
  docker container prune
  ```
- Filter output using `--filter`:  
  ```sh
  docker ps --filter "status=exited"
  docker images --filter "dangling=true"
  ```

#### **Aliases for Productivity**  
Add these to your shell config (`~/.bashrc` or `~/.zshrc`):  
```sh
alias dps='docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"'
alias dimg='docker images --format "table {{.ID}}\t{{.Repository}}\t{{.Tag}}"'
```

#### **Common Use Cases**  
1. **Run a temporary MySQL instance**:  
   ```sh
   docker run --rm -e MYSQL_ROOT_PASSWORD=pass -p 3306:3306 mysql:latest
   ```
2. **Debug a container interactively**:  
   ```sh
   docker exec -it my_container /bin/bash
   ```
3. **Copy config files from host to container**:  
   ```sh
   docker cp ./config.json my_container:/app/config.json
   ```

#### **Gotchas & Best Practices**  
⚠️ **Avoid running as root**: Use `USER` directive in Dockerfiles.  
⚠️ **Limit resources**: Set CPU/memory limits with `--cpus`, `--memory`.  
✅ **Use `.dockerignore`**: Speed up builds by excluding unnecessary files.  
