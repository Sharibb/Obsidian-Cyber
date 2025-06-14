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


