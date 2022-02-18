#!/bin/sh
set -e
set -x

# disable CGO for cross-compiling
export CGO_ENABLED=0

# compile for all architectures
GOOS=linux   GOARCH=amd64   go build -ldflags "-X main.version=${DRONE_TAG##v}" -o release/linux/amd64/proxmoxsd       ./proxmoxsd
GOOS=linux   GOARCH=arm64   go build -ldflags "-X main.version=${DRONE_TAG##v}" -o release/linux/arm64/proxmoxsd       ./proxmoxsd
GOOS=linux   GOARCH=ppc64le go build -ldflags "-X main.version=${DRONE_TAG##v}" -o release/linux/ppc64le/proxmoxsd       ./proxmoxsd
GOOS=linux   GOARCH=arm     go build -ldflags "-X main.version=${DRONE_TAG##v}" -o release/linux/arm/proxmoxsd         ./proxmoxsd
GOOS=windows GOARCH=amd64   go build -ldflags "-X main.version=${DRONE_TAG##v}" -o release/windows/amd64/proxmoxsd.exe ./proxmoxsd
GOOS=darwin  GOARCH=amd64   go build -ldflags "-X main.version=${DRONE_TAG##v}" -o release/darwin/amd64/proxmoxsd      ./proxmoxsd
GOOS=darwin  GOARCH=arm64   go build -ldflags "-X main.version=${DRONE_TAG##v}" -o release/darwin/arm64/proxmoxsd      ./proxmoxsd

# tar binary files prior to upload
tar -cvzf release/proxmoxsd_linux_amd64.tar.gz   -C release/linux/amd64   proxmoxsd
tar -cvzf release/proxmoxsd_linux_arm64.tar.gz   -C release/linux/arm64   proxmoxsd
tar -cvzf release/proxmoxsd_linux_ppc64le.tar.gz -C release/linux/ppc64le proxmoxsd
tar -cvzf release/proxmoxsd_linux_arm.tar.gz     -C release/linux/arm     proxmoxsd
tar -cvzf release/proxmoxsd_windows_amd64.tar.gz -C release/windows/amd64 proxmoxsd.exe
tar -cvzf release/proxmoxsd_darwin_amd64.tar.gz  -C release/darwin/amd64  proxmoxsd
tar -cvzf release/proxmoxsd_darwin_arm64.tar.gz  -C release/darwin/arm64  proxmoxsd

# generate shas for tar files
sha256sum release/*.tar.gz > release/proxmoxsd_checksums.txt