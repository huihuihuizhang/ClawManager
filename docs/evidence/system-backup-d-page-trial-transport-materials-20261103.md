# Actual API TLS, one MinIO installer and original Vault state export

Source-only delivery. D has not executed these scripts, Go tests, any provider, SQL or field operation. Old freezes remain unchanged. Final source/asset hashes are in the accompanying unified closure and installation supplement.

## Real page-to-backend TLS

The existing nginx front end proxies API traffic to HTTP9001. A TLS edge alone cannot satisfy the actual task/config handler's Request.TLS check. New source adds a separate actual loopback TLS listener on fixed 127.0.0.1:9002 serving the SAME router and session/auth services. HTTP9001 remains for existing API/health paths. The new container helper generates a private localhost CA/server pair before either process starts; nginx verifies that exact local CA/name and uses TLS1.3 for versioned backup paths. No forwarded header manufactures Request.TLS. Existing exact proof route and ^~ evidence download route keep their original dedicated upstream precedence.

Actual switch is SYSTEM_BACKUP_API_PROXY_ENABLED=true, set by the replacement TLS-only field preparation tool before B facts. start.sh prepares the include and exports the fixed private listener/certificate paths. The generated CA signing key and CSR are removed after issuance; the server leaf key remains private0600. No provider or existing app edge CA is rotated. A container/Pod restart still invalidates B's original facts normally. Main starts and gracefully drains this real listener. Root must include /app/system-backup-api-proxy.sh and both modified nginx/start files in its offline image; merely adding the Go binary is insufficient.

The new Go test SOURCE performs an actual local TLS handshake through this configuration, then proves a plaintext request carrying X-Forwarded-Proto:https still has no TLS authority; public/arbitrary listener addresses refuse. This is transport proof only, not session/resource/config enable or task proof. Actual legal config route still needs A's complete mutation resource graph and factory instance.

## Sole C MinIO chain

Use scripts/system-backup-first-page-tls-only.py instead of the historical system-backup-first-page-minio-tls.py. It has no provision-accounts action and generates no user credentials or policies. It handles prepare/apply/rollback and export-mysql-ca exactly as the original guarded TLS operation. An additional export-minio-admin action follows actual MINIO_ROOT_USER/PASSWORD env sources to only the selected Secret keys and writes create-only raw600 files minio-original-admin-user.raw and minio-original-admin-password.raw into an operator-owned700 directory. No credential bytes or hashes print. There are no defaults or handwritten credential JSON.

After TLS, use C's sole system-backup-minio-native-install probe -> generate -> authenticated apply -> actual original permission producer -> C SQL owner/install chain. Its mc user-add uses non-TTY stdin, never a secret argv. Root's actual bundled mc is SHA01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891, not a D assertion of native permission. C source, exact native observer/source checks and existing guard window stay mandatory. The new Dockerfile candidate includes this command: final extra installation tool count22.

## Actual original Vault directory and new evidence key

The prior original provider record docs/evidence/system-backup-a-installed-provider-observation-contract-20261102.json:19 records /root/sbk-vault-owner-20261102-01. The operator alone has it; D did not access it remotely. The exact reviewed d220 installer stores init-material.json, ca.pem, state.json there. Root/unseal material has never been exported in the public report. Do not print/copy that directory into a package/Pod.

The new runnable operation is:

```sh
python3 -B scripts/system-backup-first-page-evidence-transit.py --apply \
  --installation-id "$ACTUAL_ORIGINAL_PLAN_INSTALLATION_ID" \
  --output-directory /root/sbk-first-page-evidence-key-20261103
```

Only the installation selector comes from the actual existing original plan; the operator does not write an authority/signature JSON. The script selects the fixed real state directory, validates its original namespace/cluster/Deployment/CA/image and unsealed provider, and uses the existing verified loopback TLS port-forward helper. It creates a fresh dedicated aes256-gcm96 derived nonexportable evidence key, exact existing EvidenceTransitContext and separate update-only wrap/unwrap policies plus a metadata-only observer. It creates separate 30-minute nonrenewable orphan PREPARATION tokens with no default policy. Tokens stay in private600 raw files; root/unseal are not copied into output, argv, logs or Pods. Actual encrypt/decrypt of a random32-byte preparation probe and cross-operation/wrong-context refusals check the new key/scope. No existing key rotates or is exported. Unknown/partial native outcome retains the new private intent and all original state; no automatic delete/re-sign/retry.

provider-materials.json selects the actual endpoint, cluster/CA, new logical evidence KeyRef/provider version, exact context and policy names. A's six-reference material producer must consume those actual original sources through its own real observation/issuance path and original current revocation controls. The preparation tokens are NOT future Job/task credentials or current configuration write permission, and the unsigned receipt is NOT A authority. No future Job is created to bootstrap. A still installs actual workload-bound roles/current credentials from the existing enrolled runtime when available; root must not promote the preparation receipt to successful six-reference admission.

## Remaining delivery limit

Root's actual Linux failures remain preserved. R3 fixture repairs use original RepeatableRead, full JCS and an exact missing-source set; no production validation is relaxed. The new API transport solves a concrete plaintext hop but does not fill the thirty mutation/deployment owners. Genuine historical adoption/fence/coverage sources also remain required; loader success or four rows cannot create them. D cannot honestly commit to fully legal enabling by14:00 from the currently delivered sources. Missing inputs must become an exact observed failure, not a fabricated ready state.
