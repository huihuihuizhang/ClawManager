# 08:30 生产 MySQL 公开证书观察

先在远程 Bash 执行下列完整代码块，再执行 [R8 原窗口诊断](system-backup-supervisor-next-remote-20261103.md)。它只读取已知 MySQL Pod 的身份和默认路径中的公开证书元数据；无需提供数据库密码。

目标沿用此前现场记录。Pod、镜像或 namespace 身份不符时停止此项，保留拒绝输出，不自动选择另一个目标。公开文件观察不证明运行中的 MySQL 使用这份证书；真实 TLS 握手及 source、installer、consumer 三类账户权限仍须正式 observer 验证。

```bash
if (
  set -euo pipefail
  set +x
  CONTEXT='kubernetes-admin@kubernetes'
  NS='clawmanager-zhanghui08-system'
  NS_UID='337cfe30-2c17-4b8e-b32a-760778b8098e'
  POD='mysql-74bd777b8-j85z7'
  EXPECTED_IMAGE='10.130.14.23:5000/mysql@sha256:5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977'
  kcmd=(kubectl --context "$CONTEXT" --namespace "$NS")
  observed_ns=$(kubectl --context "$CONTEXT" get namespace "$NS" -o 'jsonpath={.metadata.uid}')
  if [[ "$observed_ns" != "$NS_UID" ]]; then
    printf 'mysql_public_cert_status=refused namespace_identity_changed\n'
    exit 2
  fi
  pod_uid=$("${kcmd[@]}" get pod "$POD" -o 'jsonpath={.metadata.uid}')
  image_id=$("${kcmd[@]}" get pod "$POD" -o 'jsonpath={.status.containerStatuses[?(@.name=="mysql")].imageID}')
  if [[ -z "$pod_uid" || "$image_id" != "$EXPECTED_IMAGE" ]]; then
    printf 'mysql_public_cert_status=refused pod_or_image_changed\n'
    exit 2
  fi
  printf 'scope=production-public-certificate-files-only\nnamespace_uid=%s\npod=%s\npod_uid=%s\nimage_id=%s\n' "$NS_UID" "$POD" "$pod_uid" "$image_id"
  "${kcmd[@]}" exec "$POD" --container mysql -- sh -c '
    set -eu
    set +x
    command -v openssl >/dev/null
    for cert in /var/lib/mysql/ca.pem /var/lib/mysql/server-cert.pem; do
      printf "public_certificate_path=%s\n" "$cert"
      if test -f "$cert"; then
        sha256sum "$cert"
        if openssl x509 -in "$cert" -noout -subject -issuer -serial -dates -fingerprint -sha256 -ext subjectAltName; then
          printf "public_certificate_parse=completed\n"
        else
          printf "public_certificate_parse=failed\n"
          exit 3
        fi
      else
        printf "public_certificate_file=not_found\n"
      fi
    done
  '
  after_uid=$("${kcmd[@]}" get pod "$POD" -o 'jsonpath={.metadata.uid}')
  after_image=$("${kcmd[@]}" get pod "$POD" -o 'jsonpath={.status.containerStatuses[?(@.name=="mysql")].imageID}')
  after_ns=$(kubectl --context "$CONTEXT" get namespace "$NS" -o 'jsonpath={.metadata.uid}')
  if [[ "$after_uid" != "$pod_uid" || "$after_image" != "$image_id" || "$after_ns" != "$NS_UID" ]]; then
    printf 'mysql_public_cert_status=refused identity_changed_during_observation\n'
    exit 2
  fi
  printf 'mysql_public_cert_status=observed_files_only\npeer_tls_and_account_qualification=unverified\n'
); then
  printf 'mysql_public_cert_exit=0\n'
else
  mysql_public_cert_rc=$?
  printf 'mysql_public_cert_exit=%s\n' "$mysql_public_cert_rc"
fi
```

请回传完整公开摘要。默认路径不存在或没有合适的 DNS/IP SAN 时，D 据此准备真实 PKI/账户安装步骤；不要通过关闭证书校验替代。此项与 R8 隔离 SQL 测试独立，失败也可继续 R8。
