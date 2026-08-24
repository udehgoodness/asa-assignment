# vulntracker Helm chart

Deploys the VulnTracker Python API (`app/`) to Kubernetes. Verified with a real `helm install` against a local cluster during development (not just `helm template`) — see the commit history for the fixes that surfaced.

## Prerequisites

- The image built from the repo-root `Dockerfile`, pushed somewhere the cluster can pull it from (or already present on the cluster's nodes, e.g. via `kind load` / Docker Desktop's shared image store for local testing)
- **Secrets**: by default this chart creates an `ExternalSecret` (`secrets.externalSecret.enabled: true`), which requires the [External Secrets Operator](https://external-secrets.io) and a `SecretStore` (`secrets.externalSecret.secretStoreRef.name`) already configured in the target namespace, pointing at your actual secrets manager (AWS Secrets Manager, GCP Secret Manager, Vault, etc.). If your cluster doesn't run ESO, set `secrets.externalSecret.enabled: false` and populate the `secrets.secretName` Secret by another means before install — the Deployment only ever references a Secret **name**, never a literal value.
- An ingress controller matching `ingress.className` (default `nginx`) if `ingress.enabled: true`
- The `notify/` service deployed separately as a Kubernetes Service — this chart assumes it's reachable at `env.NOTIFY_SERVICE_URL` and matches `networkPolicy.notifySelector` for the egress rule. Adjust both to match however you actually deploy it.

## Install

```bash
helm install vulntracker helm/vulntracker \
  --namespace vulntracker --create-namespace \
  --set ingress.host=your-real-domain.example.com \
  --set env.ALLOWED_HOSTS=your-real-domain.example.com,localhost,127.0.0.1
```

## Known limitations (see docs/executive-summary.md for the broader context)

- SQLite runs on an `emptyDir` volume — not persistent across pod reschedules, not safe to share across multiple replicas. Fine for this exercise; a real deployment needs an external database and `DATABASE_URL` pointed at it (also via the secrets-manager path, not a plaintext value).
- `replicaCount` defaults to 1 for the same reason — SQLite doesn't handle concurrent writers from multiple pods safely.
