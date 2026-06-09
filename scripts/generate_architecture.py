"""Gera o diagrama de arquitetura do projeto MLOps Phishing Detection.

Estrutura plana (sem clusters aninhados) para garantir roteamento ortogonal
limpo sem linhas cruzando blocos.
"""

from pathlib import Path

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import EC2
from diagrams.aws.storage import S3
from diagrams.aws.general import General
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.database import MongoDB
from diagrams.onprem.vcs import Github
from diagrams.programming.language import Python
from diagrams.onprem.client import User
from diagrams.programming.framework import FastAPI

OUTPUT = str(Path(__file__).parent.parent / "images" / "architecture")

graph_attr = {
    "fontsize": "12",
    "bgcolor": "white",
    "pad": "1.2",
    "splines": "ortho",
    "nodesep": "0.9",
    "ranksep": "1.1",
    "fontname": "Helvetica",
    "compound": "true",
    "remincross": "true",
}

with Diagram(
    "MLOps Phishing Detection — Architecture",
    filename=OUTPUT,
    outformat="png",
    graph_attr=graph_attr,
    show=False,
    direction="LR",
):
    # ── Coluna 1: Origem ───────────────────────────────────────────────────────
    github = Github("GitHub\nMLOps-PhishingDetection")
    user   = User("User / Browser")

    # ── Coluna 2: CI/CD ────────────────────────────────────────────────────────
    with Cluster("CI/CD — GitHub Actions"):
        ci = GithubActions(
            "1. pytest · 151 tests\n"
            "2. docker build\n"
            "3. push to ECR\n"
            "4. deploy via SSH"
        )

    # ── Coluna 3: AWS ──────────────────────────────────────────────────────────
    with Cluster("AWS — Terraform"):
        oidc = General("IAM / OIDC\nGitHub auth")
        ecr  = General("ECR\nDocker registry")
        ec2  = EC2("EC2 t3.small")
        s3   = S3("S3\nmodel.pkl")

    # ── Coluna 4: Aplicação ────────────────────────────────────────────────────
    with Cluster("Docker Container — FastAPI"):
        api = FastAPI(
            "API / UI Layer\n"
            "GET  /url-checker\n"
            "POST /predict-url  (URL mode)\n"
            "POST /predict       (CSV mode — batch)"
        )
        ssrf = Python(
            "SSRF Validator\n"
            "blocks: localhost · private IPs\n"
            "link-local · cloud metadata\n"
            "unsafe schemes"
        )
        fe = Python(
            "Feature Extractor — 30 features\n"
            "String (10) · HTTP/HTML (12)\n"
            "DNS/WHOIS (3) · External APIs (5)"
        )
        model = Python(
            "Gradient Boosting · scikit-learn\n"
            "F1 = 0.97 · Recall = 0.97"
        )

    # ── Coluna 5: Saída + Treinamento ──────────────────────────────────────────
    resp  = Python(
        "JSON Response\n"
        "prediction · confidence\n"
        "30 features · warnings"
    )

    with Cluster("Training Pipeline"):
        train = Python(
            "Data Ingestion\n"
            "Validation · Transformation\n"
            "5 Models · GridSearchCV"
        )

    # ── Coluna 6: Serviços externos ────────────────────────────────────────────
    with Cluster("External Services"):
        gsb    = General("Google Safe Browsing\nStatistical_report")
        tranco = General("Tranco API\nweb_traffic")
        mongo  = MongoDB("MongoDB Atlas\nprediction logs")

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — fluxo principal esquerda para direita
    # ═══════════════════════════════════════════════════════════════════════════

    # Source → CI/CD
    github >> Edge(label="push") >> ci

    # CI/CD → AWS
    oidc   >> Edge(style="dashed", label="OIDC auth") >> ci
    ci     >> Edge(label="push image")   >> ecr
    ci     >> Edge(label="SSH deploy")   >> ec2
    ec2    >> Edge(label="pull & run")   >> api

    # Training → S3 → Model
    train  >> Edge(label="save model.pkl")              >> s3
    s3     >> Edge(label="load model.pkl",
                   color="darkgreen", style="bold")     >> model

    # User → App
    user   >> Edge(label="URL / CSV")    >> api

    # Internal app flow
    api    >> Edge(label="validate URL") >> ssrf
    api    >> Edge(style="dashed",
                   label="CSV: direct\nto model")       >> model
    ssrf   >> Edge(label="extract\nfeatures")           >> fe
    fe     >> Edge(label="30-feature\nvector")          >> model

    # Model → Response → User
    model  >> resp
    resp   >> Edge(label="JSON")         >> user

    # Feature Extractor → External APIs
    fe     >> Edge(style="dashed",
                   label="threat\nintelligence")        >> gsb
    fe     >> Edge(style="dashed",
                   label="domain\npopularity rank")     >> tranco

    # FastAPI → MongoDB
    api    >> Edge(style="dashed",
                   label="prediction\nlogs / app data") >> mongo

print(f"Diagrama gerado: {OUTPUT}.png")
