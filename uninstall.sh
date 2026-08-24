#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the uninstaller with sudo: sudo ./uninstall.sh" >&2
  exit 1
fi

purge_config=false
if [[ ${1:-} == "--purge-config" ]]; then
  purge_config=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: sudo ./uninstall.sh [--purge-config]" >&2
  exit 2
fi

install_root="${DESTDIR:-}"
target_lib="${install_root}/usr/local/lib/safehalt"
target_doc="${install_root}/usr/local/share/doc/safehalt"

rm -f -- "${install_root}/usr/local/sbin/safehalt"
rm -f -- "${install_root}/usr/local/share/man/man8/safehalt.8"
rm -f -- "${install_root}/etc/sudoers.d/safehalt"
for module in __init__.py __main__.py cli.py config.py credentials.py errors.py platform.py quarantine.py storage.py system.py; do
  rm -f -- "${target_lib}/${module}"
done
if [[ -d ${target_lib}/__pycache__ ]]; then
  find "${target_lib}/__pycache__" -maxdepth 1 -type f -name '*.pyc' -delete
  rmdir --ignore-fail-on-non-empty "${target_lib}/__pycache__" 2>/dev/null || true
fi
rmdir --ignore-fail-on-non-empty "${target_lib}" 2>/dev/null || true
for document in README.md README.es.md SECURITY.md SECURITY_MODEL.md CHANGELOG.md LICENSE; do
  rm -f -- "${target_doc}/${document}"
done
rmdir --ignore-fail-on-non-empty "${target_doc}" 2>/dev/null || true

if ${purge_config}; then
  rm -f -- "${install_root}/etc/safehalt/credentials.json"
  rm -f -- "${install_root}/etc/safehalt/paths.json"
  rmdir --ignore-fail-on-non-empty "${install_root}/etc/safehalt" 2>/dev/null || true
  echo "Program and configuration removed. Quarantine data and manifests were preserved."
else
  echo "Program removed. Configuration, manifests and quarantine data were preserved."
fi
