"""Protocol-recognizable native-stack secret scrubber (label-free, fail-closed).

This module is the **single source of truth** for redacting authentication
material that the native AD stack (aiosmb, badauth, kerbad, badldap, …) can emit
into log lines or the session recording. It lives in ``adscan_core`` — the
dependency-light layer that ships in both the host launcher and the container
runtime — so the two consumers can share one implementation:

* :mod:`adscan_internal.services.native_log_taming` — LAYER 2 of the
  no-exfiltration defence: scrubs every line the native-stack logging bridge
  forwards, *before* it reaches the telemetry buffer or the ``--debug`` console.
* :mod:`adscan_core.telemetry` — the export-time, whole-buffer, fail-closed
  last line of defence: scrubs the exported session recording per line, so even
  material that did NOT travel through the bridge (e.g. ``--debug`` console
  mirroring of a vendor ``print()``) is redacted before upload.

================================================================================
Two redaction strategies, combined
================================================================================

1. **Protocol-recognizable, LABEL-FREE detectors** (the gap this module closes).
   Real leaks observed in the wild are NOT preceded by a known secret label, so
   the historical label-gated approach missed them entirely:

   * NTLMSSP messages — any hex run beginning with the magic ``4e544c4d53535000``
     (``NTLMSSP\\0``). Catches ``[SRV] AUTHDATA: 4e544c4d53535000...`` regardless
     of the (unknown) ``AUTHDATA`` label.
   * NetNTLMv1/v2 hashcat-format lines — ``user::DOMAIN:<hex>:<hex>[:<hex>]``.
     The crackable response is redacted; ``user::DOMAIN`` is kept (it is not the
     secret, and keeping it preserves debuggability).
   * Server/NTLM challenge byte-reprs — ``ServerChallenge: b'...'``.

2. **LABEL-GATED hex/base64 redaction** (the conservative complement). A long
   hex OR base64 run is redacted ONLY when a known secret label immediately
   precedes it (crypto keys, NTLM/Kerberos response fields, Kerberos ticket /
   enc-part / cipher blobs). This keeps false positives near zero: hostnames,
   domain names, ``NegotiateFlags: 0xe28a8215``, Kerberos etypes (``18``),
   sequence numbers and short hex are never touched because no secret label
   precedes them.

================================================================================
False-positive guard (hard requirement)
================================================================================
Every detector is anchored on a protocol-recognizable shape or a known secret
label and bounded by a minimum length, so NON-secrets stay verbatim:

* ``web01.pirate.htb`` (hostname) — never matches (no label, not hex/NTLMSSP).
* ``PIRATE`` (NetBIOS / domain) — never matches.
* ``NegotiateFlags: 0xe28a8215`` — the ``0x`` flags value is short and not
  label-gated as a secret; left untouched.
* etype ``18`` / ``0x709`` — too short for any hex floor.
* IPv4 addresses — handled by the dedicated IP sanitizer upstream; never
  matched here.

Every public function is best-effort and NEVER raises — a scrub failure must not
break the logging bridge nor weaken the telemetry export's fail-closed contract
(if the export sanitizer raises, the caller skips the upload).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Strategy 1 — protocol-recognizable, label-free detectors
# ---------------------------------------------------------------------------

# NTLMSSP signature: the 8-byte magic "NTLMSSP\0" rendered as hex. Any hex run
# that STARTS with this magic is a serialized NTLM NEGOTIATE / CHALLENGE /
# AUTHENTICATE message (the AUTHENTICATE message carries the NetNTLM response).
# We redact the entire run regardless of the (possibly unknown) preceding label.
_NTLMSSP_MAGIC_HEX = "4e544c4d53535000"
_NTLMSSP_MESSAGE_RE = re.compile(
    rf"(?i){_NTLMSSP_MAGIC_HEX}(?:[0-9a-f]{{2}})*",
)

# NetNTLMv1/v2 hashcat capture format:
#   user::DOMAIN:<hex>:<hex>[:<hex>]
# The two (or three) trailing hex fields are the crackable response material.
# We keep ``user::DOMAIN`` visible (not secret, aids debugging) and redact the
# response fields. ``[^\s:]{1,256}`` bounds the user/domain so we never run away
# across a whole line; the hex floors (>=16 chars) keep flags/etypes safe.
_NETNTLM_HASHCAT_RE = re.compile(
    r"(?i)(?P<head>(?<![A-Za-z0-9._@\\/-])[^\s:]{1,256}::[^\s:]{1,256}:)"
    r"(?P<resp>[0-9a-f]{16,}:[0-9a-f]{16,}(?::[0-9a-f]{1,})?)"
)

# Challenge byte-repr / quoted value:
#   ServerChallenge: b'Mp\xf2xj\xc1[^'   |   challenge = "....."
# We redact the quoted payload (>=4 chars) and keep the label.
_CHALLENGE_REPR_RE = re.compile(
    r"(?i)(?P<label>(?:server)?challenge)(?P<sep>\b[\s:=]*)"
    r"(?P<prefix>b?)(?P<quote>['\"])(?P<value>(?:\\.|[^'\"\\]){4,}?)(?P=quote)"
)


def _redact_ntlmssp(match: "re.Match[str]") -> str:
    blob = match.group(0)
    n_bytes = len(blob) // 2
    return f"<redacted NTLM message: {n_bytes} bytes>"


def _redact_netntlm(match: "re.Match[str]") -> str:
    return f"{match.group('head')}<redacted NetNTLM response>"


def _redact_challenge(match: "re.Match[str]") -> str:
    return (
        f"{match.group('label')}{match.group('sep')}"
        f"{match.group('prefix')}{match.group('quote')}"
        f"<redacted challenge>{match.group('quote')}"
    )


# ---------------------------------------------------------------------------
# Strategy 2 — label-gated hex / base64 redaction
# ---------------------------------------------------------------------------

# Labels that are immediately (modulo a separator) followed by raw secret
# material. Case-insensitive. The crackable / relayable material is concentrated
# here: crypto keys (seal/sign/session/key-exchange), captured NTLM/Kerberos
# challenge-response fields, and Kerberos ticket/enc-part/cipher blobs.
SECRET_LABELS: tuple[str, ...] = (
    # NTLM / SMB crypto keys.
    "sealkey",
    "signkey",
    "sessionkey",
    "session_key",
    "sessionbasekey",
    "exportedsessionkey",
    "keyexchangekey",
    "randomsessionkey",
    "encryptedrandomsessionkey",
    # NTLM / Kerberos challenge-response and crypto fields.
    "response",
    "ntchallenge",
    "lmchallenge",
    "ntproofstr",
    "challengefromclient",
    "challengefromclinet",  # upstream typo kept on purpose — match both spellings
    "serverchallenge",
    "authdata",
    "channel_binding",
    "channelbinding",
    "cipher",
    # Kerberos ticket / key material.
    "ticket",
    "enc-part",
    "encpart",
    "enc_part",
    "subkey",
    "as-rep",
    "asrep",
    "ap-req",
    "apreq",
    "tgs-rep",
    "tgsrep",
    "tgt",
    "kerberos key",
    "kerberoskey",
)

_LABEL_ALT = "|".join(re.escape(lbl) for lbl in SECRET_LABELS)

# A separator between the label and the value: optional ``to`` / whitespace /
# ``:`` / ``=`` / quotes / parens / brackets. ``(?:bytes\.)?`` is implicitly
# tolerated by the generic separator class.
_SEP = r"(?P<sep>(?:\s+to\b)?[\s:=\'\"\(\[]*)"

# Label-gated HEX run, >=16 hex chars (>= 8 bytes). Short hex (flags, seq
# numbers, etypes) is left untouched because the floor is not reached.
_LABEL_HEX_RE = re.compile(
    rf"(?i)(?P<label>{_LABEL_ALT}){_SEP}(?P<val>[0-9a-fA-F]{{16,}})"
)

# Label-gated BASE64 run, >=40 chars (Kerberos tickets / enc-parts are long).
# Conservative on purpose: only fires behind a known Kerberos/secret label so an
# ordinary long base64 token elsewhere in the buffer is never eaten. Requires at
# least one base64-only signal would be ideal, but the label gate already does
# that job; the >=40 floor avoids short tokens.
_LABEL_B64_RE = re.compile(
    rf"(?i)(?P<label>{_LABEL_ALT}){_SEP}(?P<val>[A-Za-z0-9+/]{{40,}}={{0,2}})"
)


def _redact_label_hex(match: "re.Match[str]") -> str:
    n_bytes = len(match.group("val")) // 2
    return f"{match.group('label')}{match.group('sep')}<redacted:{n_bytes} bytes>"


def _redact_label_b64(match: "re.Match[str]") -> str:
    return f"{match.group('label')}{match.group('sep')}<redacted secret blob>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scrub_native_secrets(line: str) -> str:
    """Redact native-stack authentication material from a single text line.

    Combines the protocol-recognizable, label-free detectors (NTLMSSP messages,
    NetNTLM hashcat lines, challenge byte-reprs) with the conservative
    label-gated hex/base64 redaction (crypto keys, Kerberos ticket/enc-part
    blobs). Non-secret tokens — hostnames, domain names, ``NegotiateFlags``,
    Kerberos etypes, sequence numbers, short hex, IPs — are never touched because
    every detector is anchored on a protocol shape or a known secret label and
    bounded by a minimum length.

    Best-effort and idempotent: re-running over already-redacted text is a no-op
    (the redaction markers contain no hex/NTLMSSP/base64 the detectors match).
    NEVER raises — a scrub failure must not break the logging bridge nor weaken
    the telemetry export's fail-closed contract.

    Args:
        line: A single log line or recording line.

    Returns:
        The line with native authentication material redacted.
    """
    if not line:
        return line
    try:
        # Strategy 1 — protocol-recognizable, label-free (run first; these are
        # the highest-confidence redactions and shrink the surface the
        # label-gated pass then scans).
        line = _NTLMSSP_MESSAGE_RE.sub(_redact_ntlmssp, line)
        line = _NETNTLM_HASHCAT_RE.sub(_redact_netntlm, line)
        line = _CHALLENGE_REPR_RE.sub(_redact_challenge, line)
        # Strategy 2 — label-gated hex then base64.
        line = _LABEL_HEX_RE.sub(_redact_label_hex, line)
        line = _LABEL_B64_RE.sub(_redact_label_b64, line)
        return line
    except Exception:  # noqa: BLE001 — the bridge / export must survive a bad line
        return line


def scrub_native_secrets_buffer(content: str) -> str:
    """Apply :func:`scrub_native_secrets` over an entire multi-line buffer.

    Used by the telemetry export path as a whole-buffer, fail-closed last line of
    defence: every line of the exported session recording is scrubbed so native
    authentication material is redacted even when it did NOT travel through the
    native-stack logging bridge (e.g. ``--debug`` console mirroring of a vendor
    ``print()``). Preserves the line structure (and trailing newline) of the
    input so it composes cleanly with the marker-based sanitizer.

    Best-effort: never raises.

    Args:
        content: The full exported recording text/HTML.

    Returns:
        The buffer with each line scrubbed.
    """
    if not content:
        return content
    try:
        return "\n".join(scrub_native_secrets(line) for line in content.split("\n"))
    except Exception:  # noqa: BLE001
        return content
