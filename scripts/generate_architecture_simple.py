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
    # ── Dois nós de usuário (entrada e saída) — evita linha longa de retorno ───
    user_in  = User("User / Browser\nURL mode · CSV mode")
    user_out = User("User / Browser\nJSON response")

    # ── Fluxo principal ────────────────────────────────────────────────────────
    api   = FastAPI("FastAPI App\nREST API · Web UI")
    ssrf  = Python("SSRF Validator\nSafe URL validation")
    fe    = Python("Feature Extractor\n30 phishing features")
    model = Python("ML Model\nGradient Boosting")
    resp  = Python("JSON Response\nprediction · confidence\nwarnings")

    # ── Infraestrutura ─────────────────────────────────────────────────────────
    with Cluster("CI/CD + Infrastructure"):
        cicd = GithubActions("GitHub Actions\ntest · build · deploy")
        aws  = EC2("AWS Runtime\nEC2 · Docker · ECR")
        cicd >> aws

    # ── Artefato do modelo ─────────────────────────────────────────────────────
    s3 = S3("S3 — Model Artifact\nmodel.pkl")

    # ── Dados da aplicação ─────────────────────────────────────────────────────
    mongo = MongoDB("MongoDB Atlas\nprediction logs · app data")

    # ── Inteligência externa — próxima ao Feature Extractor ───────────────────
    with Cluster("External Intelligence"):
        gsb    = General("Google Safe\nBrowsing")
        tranco = General("Tranco\nURL Ranking")

    # ═══════════════════════════════════════════════════════════════════════════
    # Fluxo principal — esquerda para direita sem loop de retorno
    # ═══════════════════════════════════════════════════════════════════════════
    user_in >> Edge(label="URL / CSV") >> api
    api     >> ssrf
    ssrf    >> fe
    fe      >> model
    model   >> resp
    resp    >> Edge(label="JSON")      >> user_out

    # ═══════════════════════════════════════════════════════════════════════════
    # Fluxos de apoio
    # ═══════════════════════════════════════════════════════════════════════════

    # Infraestrutura → aplicação
    aws >> Edge(label="runs container") >> api

    # S3 → modelo (artefato)
    s3  >> Edge(label="model artifact") >> model

    # External Intelligence → Feature Extractor
    gsb    >> Edge(style="dashed") >> fe
    tranco >> Edge(style="dashed") >> fe

    # FastAPI → MongoDB
    api >> Edge(style="dashed",
                label="prediction logs /\napp data") >> mongo

print(f"Diagrama gerado: {OUTPUT}.png")
