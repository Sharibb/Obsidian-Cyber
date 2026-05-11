# Building a Fully Portable LaZagne Standalone Binary for Linux

## Overview

This documentation explains how to:

- Build a standalone Linux LaZagne binary using PyInstaller
- Resolve Python 3.13 compatibility issues
- Fix missing module/runtime issues
- Handle `dbus-python` compilation problems
- Resolve `_crypt` module issues
- Avoid GLIBC incompatibility problems
- Build portable binaries using Docker
- Create reusable Dockerfiles for different GLIBC targets

---

# Why This Is Needed

Modern Linux systems often ship with:
- Python 3.13+
- newer GLIBC versions

LaZagne has compatibility issues with:
- Python 3.13
- missing `_crypt`
- dynamic imports
- PyInstaller module discovery
- newer GLIBC portability

A binary built on:
- Kali rolling
- WSL
- Ubuntu 24+
may NOT run on older servers.

Example error:

```bash
[PYI-3504:ERROR] Failed to load Python shared library
GLIBC_2.38 not found
```

---

# Root Problems Encountered

## 1. Python 3.13 Issues

Errors:

```bash
The required _crypt module was not built as part of CPython
```

Cause:
- Python 3.13 removed/deprecated older functionality
- LaZagne compatibility issues

Fix:
- Use Python 3.11

---

## 2. PyInstaller Missing Dynamic Imports

Errors:

```bash
No module named 'lazagne.softwares.*'
```

Cause:
- LaZagne uses dynamic imports
- PyInstaller misses them unless custom hooks are loaded

Critical fix:

```bash
--additional-hooks-dir=.
```

---

## 3. dbus-python Build Failures

Errors:

```bash
Dependency "dbus-1" not found
Dependency "glib-2.0" not found
```

Fix:
Install development libraries.

---

## 4. GLIBC Incompatibility

Error:

```bash
GLIBC_2.38 not found
```

Cause:
- Binary built on newer Linux
- Target server had older GLIBC

Fix:
- Build inside older Docker image
- Match target GLIBC

---

# Final Recommended Architecture

| Component | Recommended |
|---|---|
| Python | 3.11 |
| Build Environment | Docker |
| Base OS | Ubuntu 20.04 |
| Target GLIBC | 2.31 |
| Builder | PyInstaller |

---

# Recommended Directory Layout

```text
LaZagne/
├── Linux/
│   ├── laZagne.py
│   ├── hook-sys.py
│   ├── lazagne/
│   └── ...
├── requirements.txt
```

---

# Step 1 — Install Docker

## Kali/Debian

```bash
sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker
```

Verify:

```bash
docker --version
```

---

# Step 2 — Run Portable Build Container

## Linux

```bash
docker run -it \
-v $(pwd):/opt/LaZagne \
ubuntu:20.04
```

## Windows PowerShell

```powershell
docker run -it -v "D:\pentesting\tools\LaZagne:/opt/LaZagne" ubuntu:20.04
```

---

# Step 3 — Install Build Dependencies

Inside container:

```bash
apt update

apt install -y \
python3 \
python3-pip \
python3-venv \
build-essential \
git \
pkg-config \
libdbus-1-dev \
libglib2.0-dev \
libcrypt-dev
```

---

# Step 4 — Create Virtual Environment

```bash
cd /opt/LaZagne/Linux

python3 -m venv venv

source venv/bin/activate
```

---

# Step 5 — Install Python Dependencies

## Install PyInstaller + Crypto

```bash
pip install -U pip setuptools wheel

pip install \
pyinstaller \
pycryptodome \
dbus-python
```

## Install LaZagne Requirements

```bash
cd ..

pip install -r requirements.txt

cd Linux
```

---

# Step 6 — Build Standalone Binary

## IMPORTANT

This is the critical build command:

```bash
pyinstaller \
--clean \
--additional-hooks-dir=. \
--hidden-import=Crypto \
--hidden-import=dbus \
-F --onefile laZagne.py
```

---

# Why `--additional-hooks-dir=.` Matters

LaZagne ships custom PyInstaller hooks.

Without:

```bash
--additional-hooks-dir=.
```

PyInstaller fails to resolve dynamic imports.

This causes:

```bash
No module named 'lazagne.softwares.*'
```

The hook file:

```text
hook-sys.py
```

must be loaded.

---

# Step 7 — Locate Output Binary

Final binary:

```bash
dist/laZagne
```

Run:

```bash
./dist/laZagne
```

---

# Runtime Requirements on Target Server

## NOT Required

- Python
- pip
- pycryptodome
- dbus-python

All embedded into binary.

---

## Required

### Compatible Architecture

Target must be:

```text
x86_64 Linux
```

---

### Compatible GLIBC

Check target:

```bash
ldd --version
```

Example:

```bash
GLIBC 2.31
```

Your build environment MUST use:
- same
- or older GLIBC

Never newer.

---

# Understanding GLIBC Compatibility

## BAD

Built on:
- GLIBC 2.38

Target:
- GLIBC 2.31

Fails.

---

## GOOD

Built on:
- GLIBC 2.31

Target:
- GLIBC 2.38

Works.

---

# Recommended Base Images

| Target Systems | Docker Base |
|---|---|
| Ubuntu 20.04 | ubuntu:20.04 |
| Debian 11 | debian:11 |
| Very old systems | debian:10 |

---

# Robust Reusable Dockerfile

## Dynamic GLIBC-Compatible Builder

```dockerfile
ARG BASE_IMAGE=ubuntu:20.04

FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    git \
    pkg-config \
    libdbus-1-dev \
    libglib2.0-dev \
    libcrypt-dev

WORKDIR /opt/LaZagne

COPY . /opt/LaZagne

WORKDIR /opt/LaZagne/Linux

RUN python3 -m venv venv

RUN /bin/bash -c "\
    source venv/bin/activate && \
    pip install -U pip setuptools wheel && \
    pip install pyinstaller pycryptodome dbus-python && \
    cd .. && \
    pip install -r requirements.txt && \
    cd Linux && \
    pyinstaller \
    --clean \
    --additional-hooks-dir=. \
    --hidden-import=Crypto \
    --hidden-import=dbus \
    -F --onefile laZagne.py"
```

---

# Build Using Dockerfile

## Ubuntu 20.04 / GLIBC 2.31

```bash
docker build \
--build-arg BASE_IMAGE=ubuntu:20.04 \
-t lazagne-builder .
```

## Debian 11

```bash
docker build \
--build-arg BASE_IMAGE=debian:11 \
-t lazagne-builder .
```

---

# Extract Final Binary

```bash
docker create --name extract lazagne-builder

docker cp extract:/opt/LaZagne/Linux/dist/laZagne .

docker rm extract
```

---

# Common Errors and Fixes

## Error

```bash
No module named 'dbus'
```

Fix:

```bash
apt install libdbus-1-dev libglib2.0-dev pkg-config
pip install dbus-python
```

---

## Error

```bash
Dependency "glib-2.0" not found
```

Fix:

```bash
apt install libglib2.0-dev
```

---

## Error

```bash
The required _crypt module was not built
```

Fix:

```bash
apt install libcrypt-dev
```

Rebuild Python afterwards if using pyenv.

---

## Error

```bash
GLIBC_2.xx not found
```

Fix:
- Build on older Linux
- Match target GLIBC

---

## Error

```bash
No module named 'lazagne.softwares.*'
```

Fix:

```bash
--additional-hooks-dir=.
```

---

# Testing Binary Portability

Check dependencies:

```bash
ldd ./laZagne
```

Check GLIBC requirements:

```bash
strings ./laZagne | grep GLIBC
```

---

# Recommended Production Strategy

## Best Practice

Always:
- build in Docker
- target oldest supported GLIBC
- use Python 3.11
- use Ubuntu 20.04 or Debian 11

This maximizes compatibility.

---

# Final Working Build Command

```bash
pyinstaller \
--clean \
--additional-hooks-dir=. \
--hidden-import=Crypto \
--hidden-import=dbus \
-F --onefile laZagne.py
```

---

# Final Notes

The binary is:
- standalone
- portable
- Python-independent

BUT:
- still dynamically linked to GLIBC

Therefore:
- build environment matters
- GLIBC version matters
- Docker is the safest solution for reproducible builds.
