'use strict';
module.exports = [
  { target: 'x86_64-apple-darwin', suffix: 'darwin-x64', os: 'darwin', cpu: 'x64' },
  { target: 'aarch64-apple-darwin', suffix: 'darwin-arm64', os: 'darwin', cpu: 'arm64' },
  { target: 'x86_64-unknown-linux-gnu', suffix: 'linux-x64-gnu', os: 'linux', cpu: 'x64', libc: 'glibc' },
  { target: 'aarch64-unknown-linux-gnu', suffix: 'linux-arm64-gnu', os: 'linux', cpu: 'arm64', libc: 'glibc' },
  { target: 'x86_64-pc-windows-msvc', suffix: 'win32-x64-msvc', os: 'win32', cpu: 'x64' },
  { target: 'aarch64-pc-windows-msvc', suffix: 'win32-arm64-msvc', os: 'win32', cpu: 'arm64' },
];
