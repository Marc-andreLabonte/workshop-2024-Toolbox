FROM quay.io/jupyter/base-notebook
USER root
# Install i386 support
RUN apt-get update && \
    dpkg --add-architecture i386 && \
    apt-get install -y gcc \
                       gcc-multilib \
                       make \
                       cmake \
                       git \
                       bash

#RUN apt-get install -y gcc-arm-linux-gnueabi
RUN apt-get install -y qemu-user
RUN apt-get install -y binutils-arm-linux-gnueabi
RUN apt-get install -y zlib1g-dev

RUN mkdir -p /mnt && cd /mnt && \
  git clone -q --depth 100 https://github.com/radareorg/radare2.git && \
  cd radare2 && \
  ./configure --prefix=/usr && \
  make && \
  make symstall


USER jovyan
# Install in the default python3 environment
RUN pip install --no-cache-dir 'flake8' && \
    fix-permissions "${CONDA_DIR}" && \
    fix-permissions "/home/${NB_USER}"

# Install from the requirements.txt file
COPY --chown=${NB_UID}:${NB_GID} requirements.txt /tmp/
RUN pip install --no-cache-dir --requirement /tmp/requirements.txt && \
    fix-permissions "${CONDA_DIR}" && \
    fix-permissions "/home/${NB_USER}"

COPY --chown=${NB_UID}:${NB_GID} angr /home/${NB_USER}/angr
COPY --chown=${NB_UID}:${NB_GID} unicorn /home/${NB_USER}/unicorn
COPY --chown=${NB_UID}:${NB_GID} qiling /home/${NB_USER}/qiling
