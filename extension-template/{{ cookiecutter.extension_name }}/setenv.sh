#!/bin/sh
export PACKAGE_NAME="{{ cookiecutter.extension_name.lower().replace(' ', '-').replace('_', '-') }}"
export VERSION="{{ cookiecutter.extension_version }}"
export MAINTAINER="{{ cookiecutter.maintainer }}"
export DESCRIPTION="{{ cookiecutter.extension_description }}"
