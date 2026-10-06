#!/bin/bash

# SPDX-FileCopyrightText: GARDENA GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Install a config backend server (with devel features) to be used for API tests.
# Copy files to serve and test certificates to the installation location.

set -eu -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

test_server_install_dir="$script_dir/../test-server"
rm -rf  "$test_server_install_dir"
mkdir -p "$test_server_install_dir"

cargo install --locked --force --path "$script_dir/../.." --root "$test_server_install_dir" --features "nongwhw"

cp -rf "$script_dir/../../www" "$test_server_install_dir/bin"
cp -rf "$script_dir/../../test-fixtures/" "$test_server_install_dir/bin"
