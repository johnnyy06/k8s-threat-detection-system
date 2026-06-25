# ML inference — varianta "live in-cluster" (Deployment)

Împachetarea lui [`infer_live.py`](../infer_live.py) ca **Deployment** in-cluster. Echivalentă
funcțional cu rularea scriptului pe laptop (același model, aceleași feature-uri, același index
`security-ml-*`, aceleași rezultate), dar:

- **always-on** + **self-healing** (K8s repornește pod-ul dacă pică),
- **independent de laptop** (rulează 24/7 în cluster),
- **path direct** spre ES intern `10.11.0.3:9200` (fără floating IP / NAT),
- **declarativ** (manifest în repo, ca Falco/Talon) - claim-ul Cap E "pipeline ML live integrat".

> Nu schimbă NIMIC la detecție - e doar forma de rulare. Pe acest cluster (disk I/O bottleneck,
> fără registry, fără docker pe laptop) artefactele sunt committate pentru reproducibilitate /
> Anexe; deploy-ul efectiv e opțional (go/no-go separat).

## Componente

| Fișier | Rol |
|---|---|
| [`../Dockerfile`](../Dockerfile) | imagine `python:3.12-slim` + `requirements-infer.txt` + cod + model copt |
| [`../requirements-infer.txt`](../requirements-infer.txt) | deps fixate (scikit-learn 1.9.0 = versiunea modelului) |
| [`deployment.yaml`](deployment.yaml) | Namespace `ml-ids` + Deployment `ml-infer` (nodeSelector node-2, ES_URL intern) |

Codul citește `ES_URL` din env (implicit floating IP pe laptop; suprascris la `10.11.0.3:9200` în pod).

## Runbook deploy (cluster fără registry → sideload)

```bash
# Tag cu prefix localhost/ - deterministic: docker SI podman pastreaza exact acest nume in
# containerd dupa import (= image-ul din deployment.yaml, imagePullPolicy: Never).

# 1) Build imagine (necesita docker/podman)
cd ml-ids
docker build -t localhost/ml-infer:latest -f Dockerfile .

# 2) Export + sideload pe nodul tinta (node-2) in containerd-ul MicroK8s
docker save localhost/ml-infer:latest -o /tmp/ml-infer.tar
scp -i <key.pem> /tmp/ml-infer.tar ubuntu@<node-2-floating-ip>:~/
ssh -i <key.pem> ubuntu@<node-2-floating-ip> 'sudo microk8s ctr image import ~/ml-infer.tar && rm ~/ml-infer.tar'
#   verifica: sudo microk8s ctr images ls | grep ml-infer
# (alternativ, cel mai curat aici: build DIRECT pe node-2 - eviti complet scp-ul tar-ului de 500MB)

# 3) Apply
kubectl apply -f k8s/deployment.yaml
kubectl -n ml-ids rollout status deploy/ml-infer
kubectl -n ml-ids logs -f deploy/ml-infer    # "scorate N flow-uri -> X ATTACK / Y BENIGN" la fiecare 30s
```

## Rollback

```bash
kubectl delete -f k8s/deployment.yaml          # sterge Deployment + namespace
```
Indexul `security-ml-*` rămâne (read-only pe `security-*`; nimic distructiv).

## Note / decizii

- **nodeSelector node-2**: pod-ul e client ES (placement neutru fata de fluxul de date - NU depinde de
  senzorul local). node-2 are cel mai mult headroom in steady-state (attack-pod idle) si lasa
  aplicatiile-tinta de pe node-3 (DVWA/Juice Shop) neimpactate. NU node-1 (dqlite), NU node-4 (ELK).
- **Modelul copt în imagine** (2.2MB): ConfigMap e limitat la 1MB → nu se poate monta așa.
- **`imagePullPolicy: IfNotPresent`**: imagine sideload-ată, nu dintr-un registry (clusterul n-are unul;
  addon-ul `registry` evitat - hammer pe dqlite, vezi observability în CLAUDE.md).
- **Resurse**: inferența RF e ieftină; limita 512Mi acoperă RSS-ul pandas+sklearn (~300-400MB).
