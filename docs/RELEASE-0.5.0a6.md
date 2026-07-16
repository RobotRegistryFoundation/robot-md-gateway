# Release 0.5.0a6 — signed receipts on the wire

Adds the Ed25519-signed outcome to the `/v1/invoke` HTTP response (ALLOW + 403
DENY) plus an explicit `unattested` marker, an independent
`scripts/verify_receipt.py`, and tests. See CHANGELOG.md for details.

## Build (done locally — no GitHub Actions per standing rule)

```bash
cd ~/projects/robot-md-gateway
python -m build            # -> dist/robot_md_gateway-0.5.0a6{.tar.gz,-py3-none-any.whl}
twine check dist/*         # both PASSED
```

The wheel + sdist are already built and validated under `dist/`.

## Publish — OPERATOR ACTION REQUIRED

No PyPI/TestPyPI credentials are configured in this environment, so the upload
was **not** performed. Run ONE of the following to complete acceptance
criterion 5 (a new version listed on an index):

TestPyPI (recommended first):

```bash
twine upload --repository testpypi dist/robot_md_gateway-0.5.0a6*
# verify:
pip index versions robot-md-gateway --index-url https://test.pypi.org/simple/
# or open: https://test.pypi.org/project/robot-md-gateway/0.5.0a6/
```

Real PyPI (when ready):

```bash
twine upload dist/robot_md_gateway-0.5.0a6*
pip index versions robot-md-gateway   # should list 0.5.0a6
```

Credentials: set `TWINE_USERNAME=__token__` and `TWINE_PASSWORD=<api-token>`
(or add a `[testpypi]` / `[pypi]` section to `~/.pypirc`).

## Independent receipt verification

```bash
# capture a receipt from a running gateway (attestation configured):
curl -s -X POST http://127.0.0.1:8080/v1/invoke -H 'Content-Type: application/json' \
  -d '{"msg_id":"r1","type":"INVOKE","ruri":"rcan://.../00000999","scope":"READ",
       "tool_name":"mcp__robot__render","tool_args":{},"manifest_path":"/path/ROBOT.md"}' \
  > receipt.json

# verify against the gateway attestation kid's PUBLIC key (exit 0 == authentic + tamper-evident):
python scripts/verify_receipt.py --receipt receipt.json --pubkey gw-attest.pub
```
