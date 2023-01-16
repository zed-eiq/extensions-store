#!/bin/bash

# setting up env variables provided on project initialization
if [ -e setenv.sh ]
then
    source setenv.sh
fi

# Setting up default values in case something is not provided
_ARCHITECTURE='any'
_VERSION='1.0'
: "${ARCHITECTURE:=${_ARCHITECTURE}}"
: "${VERSION:=${_VERSION}}"

export GPG_TTY=$(tty) # Fix GPG error: Inappropriate ioctl for device

function usage {
      echo "Creates and signs a package for your extension."
      echo ""
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Example: $0 -p my-extension -v 1.1 -m 'John Doe <user@example.com>' -d 'Lorem ipsum dolor' -k F8120DBF852F77C1 --source /opt/dev/my-extension"
      echo ""
      echo "Options:"
      echo "   -p package_name                  Package name. Must only contain lowercase alphanumeric and '-+' characters."
      echo "   -v version                       Numeric version of your package. Default: ${_VERSION}"
      echo "   -a arch                          Target architecture: amd64, x86. Default: ${_ARCHITECTURE}"
      echo "   -m John Doe <user@example.com>   Maintainer's contact details."
      echo "   -d description                   Description of the extension."
      echo "   --source /path/to/src            Directory containing files to be packaged."
      echo "   -k key_id                        GPG KEY_ID to be used for package signing"
      echo "   -h                               Display this."
      exit 1
}

# If no arguments provided
if [[ $# -eq 0 ]]; then
   usage
fi

# Parsing arguments here
while [ ! -z "$1" ]; do
  case "$1" in
    -p)
      shift
      PACKAGE_NAME="$1"
      echo "Name: $PACKAGE_NAME"
      ;;
    -v)
      shift
      VERSION="$1"
      echo "Version: $VERSION"
      ;;
    -a)
      shift
      ARCHITECTURE="$1"
      echo "Architecture: $ARCHITECTURE"
      ;;
    -m)
      shift
      MAINTAINER="$1"
      echo "Maintainer: $MAINTAINER"
      ;;
    -d)
      shift
      DESCRIPTION="$1"
      echo "Description: $DESCRIPTION"
      ;;
    --source)
      shift
      SRC_DIR="$1"
      echo "Directory containing files to package: $SRC_DIR"
      ;;
    -k)
      shift
      KEY_ID="$1"
      echo "GPG key id to sign package with: $KEY_ID"
      ;;
    -h)
      usage
      ;;
  esac
shift
done

#Creating package structure
TARGET_NAME="${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}"
BUILD_DIR="${TARGET_NAME}"
rm -rf ${BUILD_DIR}
mkdir -p $BUILD_DIR/$PACKAGE_NAME

# Copy executable to target folder
cp -r $SRC_DIR/* $BUILD_DIR/$PACKAGE_NAME

# Packing
tar -C $BUILD_DIR -czf $TARGET_NAME.tar.gz $PACKAGE_NAME

# Signing
gpg --local-user $KEY_ID --sign $TARGET_NAME.tar.gz

# Cleanup
rm $TARGET_NAME.tar.gz
rm -rf ${BUILD_DIR}
