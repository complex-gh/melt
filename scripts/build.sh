#!/bin/bash
# Build script for melt - creates binaries for multiple platforms

set -e

VERSION=${1:-"dev"}
BUILD_DIR="dist"

# Create build directory
mkdir -p "$BUILD_DIR"

echo "Building melt binaries..."

# Build for current platform
echo "Building for current platform..."
go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/melt" ./cmd/melt

# Build for Linux
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/melt-linux-amd64" ./cmd/melt

# Build for Windows
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/melt-windows-amd64.exe" ./cmd/melt

# Build for macOS Intel
echo "Building for macOS (Intel)..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/melt-darwin-amd64" ./cmd/melt

# Build for macOS ARM64
echo "Building for macOS (ARM64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/melt-darwin-arm64" ./cmd/melt

echo "Build complete! Binaries are in $BUILD_DIR/"
ls -lh "$BUILD_DIR/"

