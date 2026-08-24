#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the installer with sudo: sudo ./install.sh" >&2
  exit 1
fi

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_root="${DESTDIR:-}"
runtime_bin="/usr/local/sbin/safehalt"
runtime_lib="/usr/local/lib/safehalt"
target_bin="${install_root}${runtime_bin}"
target_lib="${install_root}${runtime_lib}"
target_doc="${install_root}/usr/local/share/doc/safehalt"
target_man="${install_root}/usr/local/share/man/man8/safehalt.8"
target_sudoers="${install_root}/etc/sudoers.d/safehalt"
target_config="${install_root}/etc/safehalt"
target_state="${install_root}/var/lib/safehalt/manifests"

install -d -m 0755 "${target_lib}"
for module in __init__.py __main__.py cli.py config.py credentials.py errors.py platform.py quarantine.py storage.py system.py; do
  install -m 0644 "${project_dir}/src/safehalt/${module}" "${target_lib}/${module}"
done
install -D -m 0755 "${project_dir}/bin/safehalt" "${target_bin}"
install -d -m 0700 "${target_config}" "${target_state}"
install -d -m 0755 "${target_doc}"
for document in README.md SECURITY.md SECURITY_MODEL.md CHANGELOG.md LICENSE; do
  install -m 0644 "${project_dir}/${document}" "${target_doc}/${document}"
done
install -D -m 0644 "${project_dir}/docs/README.es.md" "${target_doc}/README.es.md"
install -D -m 0644 "${project_dir}/man/safehalt.8" "${target_man}"
install -d -m 0755 "$(dirname -- "${target_sudoers}")"

if command -v visudo >/dev/null 2>&1; then
  temporary_sudoers="$(mktemp)"
  trap 'rm -f -- "${temporary_sudoers:-}"' EXIT
  sed "s|@COMMAND_PATH@|${runtime_bin}|g" \
    "${project_dir}/packaging/safehalt.sudoers.in" >"${temporary_sudoers}"
  visudo -cf "${temporary_sudoers}" >/dev/null
  install -m 0440 "${temporary_sudoers}" "${target_sudoers}"
else
  echo "Warning: visudo was not found; sudo timestamp hardening was skipped." >&2
fi

if [[ -z ${install_root} ]] && command -v mandb >/dev/null 2>&1; then
  mandb -q >/dev/null 2>&1 || true
fi

echo "SafeHalt was installed. Continue with:"
echo "  safehalt doctor"
echo "  sudo safehalt setup"
echo "  sudo safehalt status"
