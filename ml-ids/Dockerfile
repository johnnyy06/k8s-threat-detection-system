# Imagine pentru pipeline-ul ML live (infer_live.py) rulat ca Deployment in-cluster.
# Varianta "live in-cluster" a integrarii ML (Cap E) - echivalenta functional cu rularea
# scriptului pe laptop, dar always-on + self-healing + declarativa.
#
# Build (necesita docker/podman):
#   cd ml-ids && docker build -t ml-infer:latest -f Dockerfile .
# Apoi sideload pe un nod MicroK8s (cluster fara registry):
#   docker save ml-infer:latest -o /tmp/ml-infer.tar
#   scp /tmp/ml-infer.tar ubuntu@<node>:~/   &&   ssh ubuntu@<node> \
#     'sudo microk8s ctr image import ~/ml-infer.tar'
# Vezi k8s/README.md pentru runbook-ul complet.

# Ref complet (docker.io/library/...) - podman cu config Ubuntu default poate esua la
# rezolvarea numelui scurt "python:3.12-slim" ("short-name resolution").
FROM docker.io/library/python:3.12-slim

WORKDIR /app

# Deps fixate (scikit-learn 1.9.0 = versiunea cu care e serializat modelul)
COPY requirements-infer.txt ./
RUN pip install --no-cache-dir -r requirements-infer.txt

# Cod (infer_live importa collect_cluster_data pt feature-extract) + model.
# Modelul e mic (2.2MB) => copt in imagine (ConfigMap e limitat la 1MB).
COPY collect_cluster_data.py infer_live.py ./
COPY models/rf_cluster.joblib ./models/rf_cluster.joblib

# ES_URL e suprascris din Deployment (IP intern node-4). Valoarea de aici = fallback.
ENV ES_URL=http://10.11.0.3:9200

# Inferenta continua: poll la 30s, fereastra glisanta, upsert pe flow_id.
ENTRYPOINT ["python", "infer_live.py", "--watch", "--interval", "30"]
