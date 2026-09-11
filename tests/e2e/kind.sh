#!/usr/bin/env bash
set -euo pipefail

CLUSTER="${KUBE_RBAC_PROXY_KIND_CLUSTER:-kube-rbac-proxy-rust-e2e}"
IMAGE="${KUBE_RBAC_PROXY_IMAGE:-kube-rbac-proxy-rust:e2e}"
NAMESPACE="kube-rbac-proxy-e2e"

cleanup() {
  if [[ "${KUBE_RBAC_PROXY_KEEP_KIND_CLUSTER:-}" == "1" ]]; then
    echo "keeping E2E cluster $CLUSTER for diagnostics" >&2
    return
  fi
  kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v kind >/dev/null
command -v kubectl >/dev/null
command -v docker >/dev/null
docker image inspect "$IMAGE" >/dev/null

kind create cluster --name "$CLUSTER" --wait 60s
kind load docker-image "$IMAGE" --name "$CLUSTER"

kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: kube-rbac-proxy-e2e
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: proxy
  namespace: kube-rbac-proxy-e2e
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy-e2e-auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: proxy
  namespace: kube-rbac-proxy-e2e
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kube-rbac-proxy-e2e-reader
  namespace: kube-rbac-proxy-e2e
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: ServiceAccount
  name: proxy
  namespace: kube-rbac-proxy-e2e
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: proxy-config
  namespace: kube-rbac-proxy-e2e
data:
  authorization.yaml: |
    authorization:
      resourceAttributes:
        apiVersion: v1
        resource: pods
        namespace: kube-rbac-proxy-e2e
        verb: get
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: upstream
  namespace: kube-rbac-proxy-e2e
spec:
  selector:
    matchLabels:
      app: upstream
  template:
    metadata:
      labels:
        app: upstream
    spec:
      containers:
      - name: upstream
        image: registry.k8s.io/e2e-test-images/agnhost:2.53
        args: [netexec, --http-port=8080]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: upstream
  namespace: kube-rbac-proxy-e2e
spec:
  selector:
    app: upstream
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: proxy
  namespace: kube-rbac-proxy-e2e
spec:
  selector:
    matchLabels:
      app: proxy
  template:
    metadata:
      labels:
        app: proxy
    spec:
      serviceAccountName: proxy
      containers:
      - name: proxy
        image: kube-rbac-proxy-rust:e2e
        imagePullPolicy: Never
        args:
        - --upstream
        - http://upstream.kube-rbac-proxy-e2e.svc:8080
        - --secure-listen-address=0.0.0.0:8443
        - --config-file=/etc/proxy/authorization.yaml
        - --auth-header-fields-enabled
        - --proxy-endpoints-port=8081
        ports:
        - name: proxy
          containerPort: 8443
        - name: operations
          containerPort: 8081
        volumeMounts:
        - name: config
          mountPath: /etc/proxy
      volumes:
      - name: config
        configMap:
          name: proxy-config
---
apiVersion: v1
kind: Service
metadata:
  name: proxy
  namespace: kube-rbac-proxy-e2e
spec:
  selector:
    app: proxy
  ports:
  - name: proxy
    port: 8443
    targetPort: proxy
  - name: operations
    port: 8081
    targetPort: operations
YAML

kubectl -n "$NAMESPACE" rollout status deployment/upstream --timeout=180s
kubectl -n "$NAMESPACE" rollout status deployment/proxy --timeout=180s

kubectl -n "$NAMESPACE" port-forward service/proxy 18443:8443 18081:8081 >/tmp/kube-rbac-proxy-rust-port-forward.log 2>&1 &
PORT_FORWARD_PID=$!
trap 'kill "$PORT_FORWARD_PID" >/dev/null 2>&1 || true; cleanup' EXIT
for _ in $(seq 1 30); do
  if curl --silent --fail http://127.0.0.1:18081/healthz >/dev/null; then break; fi
  sleep 1
done

if curl --silent --show-error --output /dev/null --write-out '%{http_code}' http://127.0.0.1:18443/echo | grep -qx 401; then
  :
else
  echo "expected unauthenticated request to return HTTP 401" >&2
  exit 1
fi

TOKEN="$(kubectl -n "$NAMESPACE" create token proxy)"
STATUS="$(curl --silent --show-error --output /tmp/kube-rbac-proxy-rust-response.txt --write-out '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18443/hostname)"
echo "authenticated request returned HTTP $STATUS"
if test "$STATUS" != 200; then
  kubectl -n "$NAMESPACE" logs deployment/proxy --tail=80 || true
  exit 1
fi
test "$STATUS" = 200
curl --silent --fail http://127.0.0.1:18081/metrics | grep -q '^kube_rbac_proxy_requests_total '
echo "Kind E2E passed: TokenReview, SubjectAccessReview, forwarding, auth rejection, healthz, and metrics"
