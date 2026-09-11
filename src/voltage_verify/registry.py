# SPDX-License-Identifier: MIT
"""Resolve a container image reference to its content digest through the OCI registry API.

Only the manifest digest is needed to commit to an image, and a registry returns it in the
``Docker-Content-Digest`` header of a manifest request, so no image layer is downloaded.
Anonymous pull tokens are obtained by following the ``WWW-Authenticate`` challenge, which
covers Docker Hub, GHCR and most public registries. Private registries are out of scope:
pass ``--image-digest`` instead.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
USER_AGENT = "voltage-verify/0.1 (+https://voltagegpu.com)"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RegistryError(RuntimeError):
    """Raised when an image reference cannot be resolved."""


def parse_reference(reference: str) -> tuple[str, str, str]:
    """Split ``registry/repository:tag`` (or ``@digest``) into its three parts.

    Docker Hub shorthand is expanded: ``ubuntu:22.04`` becomes
    ``registry-1.docker.io/library/ubuntu:22.04``.
    """
    if "@" in reference:
        name, ref = reference.split("@", 1)
    elif ":" in reference.rsplit("/", 1)[-1]:
        name, ref = reference.rsplit(":", 1)
    else:
        name, ref = reference, "latest"
    parts = name.split("/")
    if len(parts) == 1 or ("." not in parts[0] and ":" not in parts[0] and parts[0] != "localhost"):
        registry = "registry-1.docker.io"
        repository = name if len(parts) > 1 else f"library/{name}"
    else:
        registry, repository = parts[0], "/".join(parts[1:])
    if registry == "docker.io":
        registry = "registry-1.docker.io"
    return registry, repository, ref


def _request(url: str, headers: dict[str, str], method: str = "GET") -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (https only, see below)
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read()


def _anonymous_token(www_authenticate: str) -> str | None:
    match = re.match(r'Bearer\s+(.*)', www_authenticate, flags=re.IGNORECASE)
    if not match:
        return None
    params = dict(re.findall(r'(\w+)="([^"]*)"', match.group(1)))
    realm = params.get("realm")
    if not realm or not realm.startswith("https://"):
        return None
    query = {k: v for k, v in params.items() if k in ("service", "scope")}
    status, _, body = _request(f"{realm}?{urllib.parse.urlencode(query)}", {})
    if status != 200:
        return None
    payload = json.loads(body.decode("utf-8"))
    return payload.get("token") or payload.get("access_token")


def resolve_digest(reference: str) -> str:
    """Return the ``sha256:...`` manifest digest of ``reference`` without pulling the image."""
    registry, repository, ref = parse_reference(reference)
    if DIGEST_RE.match(ref):
        return ref
    url = f"https://{registry}/v2/{repository}/manifests/{urllib.parse.quote(ref, safe='')}"
    headers = {"Accept": ACCEPT}
    status, resp_headers, _ = _request(url, headers, method="HEAD")
    if status == 401 and "www-authenticate" in resp_headers:
        token = _anonymous_token(resp_headers["www-authenticate"])
        if not token:
            raise RegistryError(f"{registry} requires authentication for {repository}")
        headers["Authorization"] = f"Bearer {token}"
        status, resp_headers, _ = _request(url, headers, method="HEAD")
    if status != 200:
        raise RegistryError(f"{registry} answered HTTP {status} for {repository}:{ref}")
    digest = resp_headers.get("docker-content-digest", "")
    if not DIGEST_RE.match(digest):
        raise RegistryError(f"{registry} returned no usable Docker-Content-Digest for {repository}:{ref}")
    return digest
