"""Gera os 3 diagramas de arquitetura do projeto MLOps Phishing Detection."""

from pathlib import Path

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import EC2
from diagrams.aws.storage import S3
from diagrams.aws.general import General
from diagrams.aws.network import ELB
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.database import MongoDB
from diagrams.onprem.vcs import Github
from diagrams.onprem.client import User
from diagrams.programming.language import Python
from diagrams.programming.framework import FastAPI

IMAGES = Path(__file__).parent.parent / "images"

BASE_ATTRS = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "1.2",
    "splines": "ortho",
    "nodesep": "0.9",
    "ranksep": "1.1",
    "fontname": "Helvetica",
    "compound": "true",
    "dpi": "72",
}

NODE_ATTRS = {
    "fontsize": "12",
    "fontname": "Helvetica",
}


# ══════════════════════════════════════════════════════════════════════════════
# DIAGRAMA 1 — APPLICATION RUNTIME ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════
with Diagram(
    "MLOps Phishing Detection — Application Runtime",
    filename=str(IMAGES / "architecture-app-runtime"),
    outformat="png",
    graph_attr=BASE_ATTRS,
    node_attr=NODE_ATTRS,
    show=False,
    direction="TB",
):
    user_in  = User("User / Browser\nURL mode · CSV mode")

    api  = FastAPI("FastAPI App\nREST API · Web UI")

    with Cluster("URL Mode — automatic feature extraction"):
        ssrf  = Python("SSRF Validator\nSafe URL validation")
        fe    = Python("Feature Extractor\n30 phishing features")

    model = Python("ML Model\nGradient Boosting")
    resp  = Python("JSON Response\nprediction · confidence · warnings")

    user_out = User("User / Browser\nJSON response")

    # apoio
    s3    = S3("S3 — Model Artifact\nmodel.pkl")
    mongo = MongoDB("MongoDB Atlas\nprediction logs · app data")

    with Cluster("External Intelligence"):
        gsb    = General("Google Safe Browsing\nStatistical_report")
        tranco = General("Tranco\nweb_traffic")

    # fluxo principal URL
    user_in >> Edge(label="URL / CSV") >> api
    api     >> ssrf
    ssrf    >> fe
    fe      >> Edge(label="30-feature vector") >> model
    model   >> resp
    resp    >> Edge(label="JSON") >> user_out

    # fluxo CSV direto
    api >> Edge(style="dashed", label="CSV: pre-extracted\nfeatures → direct") >> model

    # apoios
    s3  >> Edge(label="load model.pkl") >> model
    api >> Edge(style="dashed", label="store predictions") >> mongo
    gsb    >> Edge(style="dashed") >> fe
    tranco >> Edge(style="dashed") >> fe

print("✓ architecture-app-runtime.png")


# ══════════════════════════════════════════════════════════════════════════════
# DIAGRAMA 2 — CI/CD DEPLOYMENT ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════
with Diagram(
    "MLOps Phishing Detection — CI/CD Deployment",
    filename=str(IMAGES / "architecture-cicd-deployment"),
    outformat="png",
    graph_attr=BASE_ATTRS,
    node_attr=NODE_ATTRS,
    show=False,
    direction="LR",
):
    github = Github("GitHub\nMLOps-PhishingDetection")
    oidc   = General("IAM / OIDC\nsecure GitHub auth")

    with Cluster("GitHub Actions Pipeline"):
        step_test   = GithubActions("1. pytest\ntest suite")
        step_build  = GithubActions("2. Docker Build\nbuild image")
        step_push   = GithubActions("3. Push to ECR\nregistry upload")
        step_deploy = GithubActions("4. SSH Deploy\nto EC2")
        step_test >> step_build >> step_push >> step_deploy

    ecr = General("Amazon ECR\ncontainer registry")
    ec2 = EC2("Amazon EC2\napplication host")

    with Cluster("Production"):
        container = FastAPI("FastAPI Container\nrunning application")

    # fluxo principal
    github >> Edge(label="push to main") >> step_test
    oidc   >> Edge(style="dashed", label="OIDC auth") >> step_build
    step_push   >> Edge(label="push image") >> ecr
    step_deploy >> Edge(label="SSH deploy") >> ec2
    ec2    >> Edge(label="pull image") >> ecr
    ec2    >> Edge(label="runs") >> container

print("✓ architecture-cicd-deployment.png")


# ══════════════════════════════════════════════════════════════════════════════
# DIAGRAMA 3 — TERRAFORM AWS INFRASTRUCTURE ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════
with Diagram(
    "MLOps Phishing Detection — Terraform AWS Infrastructure",
    filename=str(IMAGES / "architecture-terraform-aws"),
    outformat="png",
    graph_attr={**BASE_ATTRS, "ranksep": "1.2"},
    node_attr=NODE_ATTRS,
    show=False,
    direction="TB",
):
    terraform = Python("Terraform\nInfrastructure as Code\n4 independent stacks")

    with Cluster("Stack 00 — Remote Backend"):
        tf_backend = S3("S3 — tfstate\n+ DynamoDB lock")

    with Cluster("Stack 01 — Storage + Registry"):
        ecr = General("Amazon ECR\nDocker image registry")
        s3  = S3("Amazon S3\nmodel.pkl · artifacts")

    with Cluster("Stack 02 — IAM + OIDC"):
        oidc = General("IAM Role\nOIDC — GitHub Actions\nkeyless authentication")

    with Cluster("Stack 03 — Compute"):
        ec2 = EC2("Amazon EC2 t3.small\napplication host")
        sg  = General("Security Group\nHTTP 8080 · SSH 22")
        ec2 - sg

    # Terraform → stacks
    terraform >> Edge(label="provisions") >> tf_backend
    terraform >> Edge(label="provisions") >> ecr
    terraform >> Edge(label="provisions") >> s3
    terraform >> Edge(label="provisions") >> oidc
    terraform >> Edge(label="provisions") >> ec2

print("✓ architecture-terraform-aws.png")
print("\nTodos os diagramas gerados em images/")
