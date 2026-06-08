ARG VARIANT="1.26-trixie"
FROM mcr.microsoft.com/vscode/devcontainers/go:${VARIANT}

SHELL ["/bin/bash", "-c"]

ARG NODE_VERSION="none"
RUN if [ "${NODE_VERSION}" != "none" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi
