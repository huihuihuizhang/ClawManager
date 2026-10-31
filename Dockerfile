FROM --platform=$BUILDPLATFORM node:24-alpine AS hermes-desktop-deps

WORKDIR /app
RUN apk add --no-cache git
COPY hermes-desktop-web/package*.json ./hermes-desktop-web/
RUN --mount=type=cache,id=clawmanager-hermes-npm,target=/root/.npm,sharing=locked npm ci --prefix hermes-desktop-web --ignore-scripts

FROM hermes-desktop-deps AS hermes-desktop-builder
COPY hermes-desktop-web/ ./hermes-desktop-web/
RUN node hermes-desktop-web/scripts/build.mjs

FROM --platform=$BUILDPLATFORM node:24-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
COPY backend/internal/teampresentation/catalog.json /app/backend/internal/teampresentation/catalog.json
ARG VITE_SYSTEM_BACKUP_LIVE_READ=1
ARG VITE_SYSTEM_BACKUP_EVIDENCE_DOWNLOAD=0
RUN case "${VITE_SYSTEM_BACKUP_LIVE_READ}:${VITE_SYSTEM_BACKUP_EVIDENCE_DOWNLOAD}" in \
      0:0|0:1|1:0|1:1) ;; \
      *) echo "Invalid system backup frontend build switches" >&2; exit 1 ;; \
    esac \
    && npm run build

FROM --platform=$BUILDPLATFORM golang:1.26.1-alpine AS backend-builder

WORKDIR /app/backend

ARG TARGETOS
ARG TARGETARCH

ARG GOPROXY
ARG GOSUMDB
ARG GOFLAGS
ENV GOFLAGS=${GOFLAGS}

RUN apk add --no-cache git

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X clawreef/internal/buildinfo.Version=${VERSION} -X clawreef/internal/buildinfo.Commit=${VCS_REF} -X clawreef/internal/buildinfo.BuildTime=${BUILD_DATE}" \
    -o /out/clawreef-server ./cmd/server \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/clawreef-northbound-gateway ./cmd/northbound-gateway \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-controller ./cmd/system-backup-controller \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-artifact ./cmd/system-backup-artifact \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/clawmanager-secret-broker ./cmd/secret-broker \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-import ./cmd/system-backup-import \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-legacy-inventory ./cmd/system-backup-legacy-inventory \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-legacy-preflight ./cmd/system-backup-legacy-preflight \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-seal-custody ./cmd/system-backup-seal-custody \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-migrate ./cmd/system-backup-migrate \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-bootstrap ./cmd/system-backup-bootstrap \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-registration ./cmd/system-backup-registration \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-controller-grants ./cmd/system-backup-controller-grants \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X clawreef/internal/buildinfo.Version=${VERSION} -X clawreef/internal/buildinfo.Commit=${VCS_REF} -X clawreef/internal/buildinfo.BuildTime=${BUILD_DATE}" -o /out/system-backup-v2-controller ./cmd/system-backup-v2-controller \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/backup-worker ./cmd/backup-worker \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/system-backup-audit-collect ./cmd/system-backup-audit-collect

# Explicit target: same source as app/controller, no server, shell or keys.
FROM scratch AS backup-worker
COPY --from=backend-builder --chmod=0555 /out/backup-worker /backup-worker
COPY --from=backend-builder --chmod=0555 /out/system-backup-seal-custody /system-backup-seal-custody
USER 65532:65532
ENTRYPOINT ["/backup-worker"]

FROM nginx:1.27-alpine AS app

# nginx-module-njs provides ngx_http_js_module.so, loaded by nginx.conf to run
# the desktop access-token verification (deployments/nginx/njs/desktop_auth.js).
RUN apk add --no-cache dumb-init openssl nginx-module-njs sqlite

WORKDIR /app

COPY --from=backend-builder /out/clawreef-server /usr/local/bin/clawreef-server
COPY --from=backend-builder /out/clawreef-northbound-gateway /usr/local/bin/clawreef-northbound-gateway
COPY --from=backend-builder /out/system-backup-controller /usr/local/bin/system-backup-controller
COPY --from=backend-builder /out/system-backup-artifact /usr/local/bin/system-backup-artifact
COPY --from=backend-builder /out/clawmanager-secret-broker /usr/local/bin/clawmanager-secret-broker
# Preserve the command used by the reviewed TLS/RBAC installation profiles.
COPY --from=backend-builder /out/clawmanager-secret-broker /usr/local/bin/clawreef-secret-broker
COPY --from=backend-builder /out/system-backup-import /usr/local/bin/system-backup-import
COPY --from=backend-builder /out/system-backup-legacy-inventory /usr/local/bin/system-backup-legacy-inventory
COPY --from=backend-builder /out/system-backup-legacy-preflight /usr/local/bin/system-backup-legacy-preflight
COPY --from=backend-builder /out/system-backup-seal-custody /usr/local/bin/system-backup-seal-custody
COPY --from=backend-builder /out/system-backup-migrate /usr/local/bin/system-backup-migrate
COPY --from=backend-builder /out/system-backup-bootstrap /usr/local/bin/system-backup-bootstrap
COPY --from=backend-builder /out/system-backup-registration /usr/local/bin/system-backup-registration
COPY --from=backend-builder /out/system-backup-controller-grants /usr/local/bin/system-backup-controller-grants
COPY --from=backend-builder /out/system-backup-v2-controller /usr/local/bin/system-backup-v2-controller
COPY --from=backend-builder /out/system-backup-audit-collect /usr/local/bin/system-backup-audit-collect
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html
COPY --from=hermes-desktop-builder /app/frontend/public/hermes-desktop-web /usr/share/nginx/html/hermes-desktop-web
COPY deployments/nginx/nginx.conf /etc/nginx/nginx.conf
COPY deployments/nginx/njs/desktop_auth.js /etc/nginx/njs/desktop_auth.js
COPY deployments/container/start.sh /app/start.sh
COPY deployments/container/system-backup-download-proxy.sh /app/system-backup-download-proxy.sh

RUN chmod +x /app/start.sh \
    && mkdir -p /etc/nginx/tls /var/log/clawreef

EXPOSE 8443 9443

ENTRYPOINT ["dumb-init", "--"]
CMD ["/app/start.sh"]
