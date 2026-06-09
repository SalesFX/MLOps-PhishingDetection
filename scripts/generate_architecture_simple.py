"""Gera o diagrama de arquitetura HIGH-LEVEL (macro) para README/portfolio."""

from pathlib import Path

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.storage import S3
from diagrams.aws.compute import EC2
from diagrams.aws.general import General
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.database import MongoDB
from diagrams.onprem.client import User
from diagrams.programming.language import Python
from diagrams.programming.framework import FastAPI

OUTPUT = str(Path(__file__).parent.parent / "images" / "architecture")

graph_attr = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "1.2",
    "splines": "ortho",
    "nodesep": "1.0",
    "ranksep": "1.2",
    "fontname": "Helvetica",
    "compound": "true",
}

node_attr = {
    "fontsize": "12",
    "fontname": "Helvetica",
}

with Diagram(
    "MLOps Phishing Detection — High-Level Architecture",
    filename=OUTPUT,
    outformat="png",
    graph_attr=graph_attr,
    node_attr=node_attr,
    show=False,
    direction="LR",
):
    # ── Entrada ────────────────────────────────────────────────────────────────
    user = User("User / Browser\nURL mode · CSV mode")

    # ── Fluxo principal (esquerda → direita) ───────────────────────────────────
    api   = FastAPI("FastAPI App\nREST API · Web UI")
    ssrf  = Python("SSRF Validator\nSafe URL validation")
    fe    = Python("Feature Extractor\n30 phishing features")
    model = Python("ML Model\nGradient Boosting")
    resp  = Python("JSON Response\nprediction · confidence\nwarnings")

    # ── Suporte: acima do fluxo principal ──────────────────────────────────────
    with Cluster("CI/CD + Infrastructure"):
        cicd = GithubActions("GitHub Actions\ntest · build · deploy")
        aws  = EC2("AWS Runtime\nEC2 · Docker · ECR")
        cicd >> aws

    # ── Suporte: abaixo do fluxo principal ─────────────────────────────────────
    s3    = S3("S3 Model Artifacts\nmodel.pkl")
    mongo = MongoDB("MongoDB Atlas\nprediction logs · app data")

    with Cluster("External Intelligence"):
        gsb    = General("Google Safe\nBrowsing")
        tranco = General("Tranco\nURL Ranking")

    # ═══════════════════════════════════════════════════════════════════════════
    # Fluxo principal — esquerda para direita
    # ═══════════════════════════════════════════════════════════════════════════
    user  >> api
    api   >> ssrf
    ssrf  >> fe
    fe    >> model
    model >> resp
    resp  >> Edge(label="JSON") >> user

    # ═══════════════════════════════════════════════════════════════════════════
    # Fluxos de apoio
    # ═══════════════════════════════════════════════════════════════════════════
    aws   >> Edge(label="runs container") >> api
    s3    >> Edge(label="load model.pkl",
                  color="darkgreen",
                  style="bold")          >> model
    gsb    >> Edge(style="dashed")       >> fe
    tranco >> Edge(style="dashed")       >> fe
    api    >> Edge(style="dashed")       >> mongo

print(f"Diagrama gerado: {OUTPUT}.png")
