#!/usr/bin/env python3
"""sanitizer_vendor_tokens_test.py

Phase 2.3 / V3 — verifies the high-signal vendor-token patterns added to
``connectors.python.sanitizer`` in v1.47:

* AWS access key IDs (``AKIA*`` / ``ASIA*``)
* GitHub tokens (``ghp_`` / ``gho_`` / ``ghu_`` / ``ghs_`` / ``ghr_``)
* Slack tokens (``xoxb-``, ``xoxp-``, ``xoxa-``, ``xapp-``)
* Stripe keys (``sk_live_`` / ``sk_test_`` / ``rk_live_`` / ``rk_test_`` /
  ``pk_live_`` / ``pk_test_`` / ``whsec_``)
* Extended connection-string schemes (``amqp``, ``clickhouse``, ``mssql``,
  ``oracle``, ``jdbc:*``)
* OpenSSH public-key blobs
* PEM-armored private-key blocks (OPENSSH / RSA / DSA / EC / PKCS#8)

Each test confirms (a) the secret value no longer appears in the sanitized
output, and (b) a deterministic placeholder marker is present. The placeholder
must never echo any part of the input back.

Run:  python connectors/python/tests/sanitizer_vendor_tokens_test.py
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))

from connectors.python.sanitizer import sanitize_log_line_for_ingest  # noqa: E402


def _assert_redacted(test, raw: str, secret: str, marker: str) -> str:
    """Sanitize ``raw``, assert the secret is gone and the marker is present."""

    out = sanitize_log_line_for_ingest(raw)
    test.assertNotIn(secret, out, f"secret leaked: {secret!r} still in {out!r}")
    test.assertIn(marker, out, f"marker missing: expected {marker!r} in {out!r}")
    return out


class AwsKeyRedactionTest(unittest.TestCase):
    def test_akia_in_bare_log(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        _assert_redacted(
            self,
            f"failed to upload: aws AccessDenied for AKIAIOSFODNN7EXAMPLE on bucket",
            secret,
            "AWS_ACCESS_KEY_ID_REDACTED",
        )

    def test_asia_temporary_credentials(self):
        secret = "ASIAY34F0R7EXAMPLE12"
        _assert_redacted(self, f"sts/{secret}/expired", secret, "AWS_ACCESS_KEY_ID_REDACTED")

    def test_unrelated_uppercase_string_not_redacted(self):
        out = sanitize_log_line_for_ingest("call ABCDEFGHIJKL12345678 ok")
        self.assertIn("ABCDEFGHIJKL12345678", out)


class GithubTokenRedactionTest(unittest.TestCase):
    def test_pat_classic(self):
        secret = "ghp_" + "a" * 36
        _assert_redacted(
            self,
            f"git fetch failed using {secret} for repo X",
            secret,
            "GITHUB_TOKEN_REDACTED",
        )

    def test_oauth(self):
        secret = "gho_" + "B" * 40
        _assert_redacted(self, f"token={secret}", secret, "GITHUB_TOKEN_REDACTED")

    def test_server_to_server(self):
        secret = "ghs_" + "9" * 36
        _assert_redacted(self, f"App token {secret} expired", secret, "GITHUB_TOKEN_REDACTED")

    def test_too_short_not_matched(self):
        # Below the 36-char minimum the spec promises; leave it alone to keep
        # false positives off random words ending in `gh<x>_…`.
        short = "ghp_short"
        out = sanitize_log_line_for_ingest(f"x={short}")
        self.assertIn(short, out)


class SlackTokenRedactionTest(unittest.TestCase):
    def test_bot_token(self):
        secret = "xoxb-1234567890-1234567890-abcdefABCDEF"
        _assert_redacted(self, f"slack post failed token={secret}", secret, "SLACK_TOKEN_REDACTED")

    def test_user_token(self):
        secret = "xoxp-0987654321-1122334455-abcDEFghi123"
        _assert_redacted(self, secret, secret, "SLACK_TOKEN_REDACTED")

    def test_app_level_token(self):
        secret = "xapp-1-A012345678-1234567890-abcdef0123456789"
        out = sanitize_log_line_for_ingest(secret)
        self.assertNotIn(secret, out)
        # xapp- matches either bot/user/app pattern; either marker is acceptable
        self.assertTrue(
            "SLACK_TOKEN_REDACTED" in out or "SLACK_APP_TOKEN_REDACTED" in out,
            f"expected a slack marker in {out!r}",
        )


class StripeKeyRedactionTest(unittest.TestCase):
    def test_sk_live(self):
        secret = "sk_live_" + "A" * 32
        _assert_redacted(self, f"Stripe::AuthenticationError {secret}", secret, "STRIPE_SECRET_KEY_REDACTED")

    def test_rk_test(self):
        secret = "rk_test_" + "z" * 28
        _assert_redacted(self, secret, secret, "STRIPE_SECRET_KEY_REDACTED")

    def test_publishable_key(self):
        secret = "pk_live_" + "p" * 24
        _assert_redacted(self, f"client side leak: {secret}", secret, "STRIPE_PUBLISHABLE_KEY_REDACTED")

    def test_webhook_secret(self):
        secret = "whsec_" + "W" * 32
        _assert_redacted(self, f"signature verify failed for {secret}", secret, "STRIPE_WEBHOOK_SECRET_REDACTED")

    def test_unknown_prefix_left_alone(self):
        # `sk_demo_…` is not a real Stripe prefix — leave it untouched so we
        # don't false-positive every short word starting with `sk_`.
        out = sanitize_log_line_for_ingest("sk_demo_short")
        self.assertIn("sk_demo_short", out)


class ConnectionStringRedactionTest(unittest.TestCase):
    def test_amqp_credentials(self):
        out = sanitize_log_line_for_ingest("connect amqp://celery:Hunter2@rabbit:5672/celery")
        self.assertNotIn("Hunter2", out)
        self.assertIn("USERNAME_REDACTED:PASSWORD_REDACTED", out)
        self.assertIn("amqp://USERNAME_REDACTED:PASSWORD_REDACTED@rabbit:5672/celery", out)

    def test_clickhouse_credentials(self):
        out = sanitize_log_line_for_ingest("clickhouses://reader:topSecretPwd@ch.internal:9440")
        self.assertNotIn("topSecretPwd", out)
        self.assertIn("clickhouses://USERNAME_REDACTED:PASSWORD_REDACTED@", out)

    def test_jdbc_credentials(self):
        out = sanitize_log_line_for_ingest("driver://jdbc:mysql://app:Secret123@db:3306/db_prod")
        self.assertNotIn("Secret123", out)
        self.assertIn("jdbc:mysql://USERNAME_REDACTED:PASSWORD_REDACTED@", out)


class SshPublicKeyRedactionTest(unittest.TestCase):
    def test_ssh_rsa_blob(self):
        secret = (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLkR6X4w7q1+e9Y6X9Lp"
            "kxQGfYrYJ9d5Vp0w0xN3J7r2P9YxTzM8aZxK1Tg5+JaB1z2NkPq5Bk5L2"
            " operator@host"
        )
        out = sanitize_log_line_for_ingest(secret)
        # whole blob should be gone
        self.assertNotIn("AAAAB3NzaC1yc2EAAAADAQABAAABAQDLkR6X4w7q1+e9Y6X9Lp", out)
        self.assertIn("SSH_PUBLIC_KEY_REDACTED", out)

    def test_ssh_ed25519_blob(self):
        secret = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzfFq8nP9Yp1F9X3ZqzYx6r7Pq+TxYxZ user"
        out = sanitize_log_line_for_ingest(secret)
        self.assertNotIn("AAAAC3NzaC1lZDI1NTE5", out)
        self.assertIn("SSH_PUBLIC_KEY_REDACTED", out)


class PrivateKeyRedactionTest(unittest.TestCase):
    """v1.47 plan-recheck follow-up — pins the ``-----BEGIN [A-Z ]+PRIVATE
    KEY-----`` multi-line pattern that's been in production since v1.47 V3
    but had no regression test. A future refactor removing that pattern
    must trip this suite, not leak a private key into ingest payloads."""

    def test_openssh_private_key_block(self):
        block = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "QyNTUxOQAAACBzfFq8nP9Yp1F9X3ZqzYx6r7PqTxYxZSampleSampleSampleSamplexx\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        out = sanitize_log_line_for_ingest(f"connect failed using key:\n{block}\n(end)")
        self.assertNotIn("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU", out)
        self.assertNotIn("AAAAtzc2gtZWQyNTUxOQ", out)
        self.assertIn("PRIVATE_KEY_REDACTED", out)

    def test_rsa_private_key_block(self):
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
            "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n"
            "-----END RSA PRIVATE KEY-----"
        )
        out = sanitize_log_line_for_ingest(block)
        self.assertNotIn("MIIEowIBAA", out)
        self.assertIn("PRIVATE_KEY_REDACTED", out)

    def test_pkcs8_private_key_block(self):
        # PKCS#8 fence has no algorithm prefix — still must match the [A-Z ]+ branch.
        block = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLkR6X4w7q1+e9\n"
            "-----END PRIVATE KEY-----"
        )
        out = sanitize_log_line_for_ingest(block)
        self.assertNotIn("MIIEvgIBADANBgkqhkiG", out)
        self.assertIn("PRIVATE_KEY_REDACTED", out)

    def test_encrypted_private_key_block(self):
        block = (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            "AAAAYourEncryptedPrivateKeyMaterialGoesHereOnMultipleLinesAAAA\n"
            "-----END ENCRYPTED PRIVATE KEY-----"
        )
        out = sanitize_log_line_for_ingest(block)
        self.assertNotIn("AAAAYourEncryptedPrivateKey", out)
        self.assertIn("PRIVATE_KEY_REDACTED", out)

    def test_unmatched_fence_left_alone(self):
        # Stray BEGIN with no matching END must not eat the rest of the log.
        # The pattern is non-greedy via [\s\S]*? and only matches when END is found.
        out = sanitize_log_line_for_ingest(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n(operator pasted partial dump)\nstack trace follows"
        )
        # No END fence in the input — the BEGIN line must NOT be silently removed
        # (otherwise an attacker could swallow surrounding log context).
        self.assertIn("stack trace follows", out)


class PlaceholderDoesNotEchoSecretTest(unittest.TestCase):
    """Defence-in-depth: every vendor-prefix placeholder is a fixed string,
    so a malicious value cannot leak through the marker (e.g. by including
    backref-looking sequences)."""

    def test_no_back_reference_leak(self):
        secret = "ghp_" + "X" * 40
        out = sanitize_log_line_for_ingest(secret)
        # The new vendor markers all live on the same line; the marker MUST
        # NOT contain any 4-or-more-char run from the original value.
        self.assertNotIn("X" * 4, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
