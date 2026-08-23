#!/usr/bin/env bash
#
# Emits the variable payload for the templates under `.github/templates/` as strict JSON on
# stdout.
#
# The manifests are the single source of truth for every number the READMEs quote: the tags the
# install snippets pin, and the MSRV the badges advertise. Deriving them here rather than
# hand-editing three files is what lets the release pull request — the commit that bumps a
# `version` — carry the matching documentation with it.
#
# The two crates release independently, so each has its own version and its own tag. The tag
# scheme is release-please's, with `include-component-in-tag` on: `<component>-v<version>`.
# Getting that wrong here would produce a README pointing at a tag that does not exist, which is
# exactly the failure the generation is meant to remove — so the shape is spelled out once, at
# the bottom, rather than assembled in three places.
#
# Run it yourself to see what CI will render with:
#
#     bash .github/scripts/readme-variables.sh
#
# Deliberately POSIX tools only, no `jq`: it is not present in a default Git for Windows shell,
# and a script that only runs on the CI runner is a script nobody checks their edit against.
set -euo pipefail

root="${1:-.}"

# Reads a top-level `key = "value"` from a manifest and rejects anything that would need JSON
# escaping. Every field read here is a version string, so the accepted alphabet is the whole
# contract — and constraining it is what makes the `printf` at the bottom safe without a JSON
# encoder.
#
# Only section-level keys can match: a dependency's version sits inside an inline table
# (`csp-policy = { version = "0.1.0", … }`) and never starts a line, so anchoring is enough.
field() {
    local manifest="$1" key="$2" pattern="$3" value

    if [ ! -f "${manifest}" ]; then
        echo "readme-variables: no such manifest: ${manifest}" >&2
        return 1
    fi

    value="$(sed -n "s/^${key} = \"\([^\"]*\)\".*/\1/p" "${manifest}" | head -n1)"

    if [ -z "${value}" ]; then
        echo "readme-variables: no top-level '${key}' in ${manifest}" >&2
        return 1
    fi

    if ! printf '%s' "${value}" | grep -Eq "${pattern}"; then
        echo "readme-variables: '${key} = \"${value}\"' in ${manifest} is not a version string" >&2
        return 1
    fi

    printf '%s' "${value}"
}

version='^[0-9A-Za-z][0-9A-Za-z.+-]*$'
release='^[0-9]+(\.[0-9]+){0,2}$'
token='^[0-9A-Za-z][0-9A-Za-z.+-]*$'

# `rust-version`, `edition` and `license` are inherited by both crates from `[workspace.package]`,
# so there is one of each and the root manifest is where it lives. The readme-variables action
# reads a member manifest and finds `rust-version.workspace = true` there, which is an absence
# rather than a value — so these three are supplied from here and merged over its payload.
msrv="$(field "${root}/Cargo.toml" rust-version "${release}")"
edition="$(field "${root}/Cargo.toml" edition "${release}")"
license="$(field "${root}/Cargo.toml" license "${token}")"
shell_version="$(field "${root}/crates/csp-shell/Cargo.toml" version "${version}")"
policy_version="$(field "${root}/crates/csp-policy/Cargo.toml" version "${version}")"

# Two shapes in one object. The flat keys are what the three templates have always read; `repo`
# and `toolchain` are objects the readme-variables action also builds, and a same-named object is
# merged key by key rather than replaced, so naming them here corrects two fields and drops
# nothing the action derived.
printf '{"msrv":"%s","shell_version":"%s","shell_tag":"csp-shell-v%s","policy_version":"%s","policy_tag":"csp-policy-v%s","repo":{"license":"%s"},"toolchain":{"msrv":"%s","edition":"%s"}}\n' \
    "${msrv}" "${shell_version}" "${shell_version}" "${policy_version}" "${policy_version}" \
    "${license}" "${msrv}" "${edition}"
