ARG VARIANT="1.22-bookworm"
FROM mcr.microsoft.com/vscode/devcontainers/go:1-${VARIANT}

ARG NODE_VERSION="none"
RUN if [ "${NODE_VERSION}" != "none" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi
