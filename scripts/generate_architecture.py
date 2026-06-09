"""Gera o diagrama de arquitetura do projeto MLOps Phishing Detection."""

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
    "pad": "1.0",
    "splines": "ortho",
    "nodesep": "0.7",
    "ranksep": "1.1",
    "fontname": "Helvetica",
}

with Diagram(
    "MLOps Phishing Detection — Architecture",
    filename=OUTPUT,
    outformat="png",
    graph_attr=graph_attr,
    show=False,
    direction="TB",
):
    # ── Source control ────────────────────────────────────────────────────────
    github = Github("GitHub\nMLOps-PhishingDetection")

    # ── CI/CD ─────────────────────────────────────────────────────────────────
    with Cluster("CI/CD — GitHub Actions"):
        ci_test   = GithubActions("1. Tests\npytest · 151 tests")
        ci_build  = GithubActions("2. Docker Build\n+ Push to ECR")
        ci_deploy = GithubActions("3. Deploy\nSSH to EC2")
        ci_test >> ci_build >> ci_deploy

    # ── AWS ───────────────────────────────────────────────────────────────────
    with Cluster("AWS — Terraform"):
        oidc = General("IAM / OIDC\nGitHub Actions auth")
        ecr  = General("Amazon ECR\nDocker registry")
        ec2  = EC2("EC2 t3.small\nDocker runtime")
        s3   = S3("S3\nmodel.pkl / artifacts")

    # ── Training (separate block) ─────────────────────────────────────────────
    with Cluster("Training Pipeline"):
        train = Python("Data Ingestion → Validation\nTransformation → 5 Models\nGridSearchCV · F1 ≥ 0.80")

    # ── Main application ──────────────────────────────────────────────────────
    with Cluster("Docker Container — FastAPI"):

        with Cluster("API / UI Layer"):
            ep_url = FastAPI("POST /predict-url\nURL Mode — automatic\nfeature extraction")
            ep_csv = FastAPI("POST /predict\nCSV Mode — batch /\ntechnical analysis")
            ep_web = FastAPI("GET /url-checker\nWeb Interface")

        with Cluster("Security"):
            ssrf = Python("SSRF Validator\nBlocks localhost · private IPs\nlink-local · cloud metadata\nunsafe schemes")

        with Cluster("Feature Extractor — 30 features"):
            fe_str  = Python("URL / String\n10 features")
            fe_http = Python("HTTP / HTML\n12 features")
            fe_dns  = Python("DNS / WHOIS\n3 features")
            fe_ext  = Python("External APIs\n5 features")

        model = Python("Gradient Boosting\nscikit-learn\nF1=0.97 · Recall=0.97")

    # ── External services ─────────────────────────────────────────────────────
    mongo  = MongoDB("MongoDB Atlas\nprediction logs / app data")
    gsb    = General("Google Safe Browsing\nStatistical_report")
    tranco = General("Tranco API\nweb_traffic")

    # ── User ──────────────────────────────────────────────────────────────────
    user = User("User / Browser")

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — CI/CD flow
    # ═══════════════════════════════════════════════════════════════════════════
    github   >> Edge(label="push to main")     >> ci_test
    oidc     >> Edge(style="dashed",
                     label="OIDC auth")        >> ci_build
    ci_build >> Edge(label="push image")       >> ecr
    ci_deploy >> Edge(label="SSH deploy")      >> ec2
    ec2      >> Edge(label="pull & run image") >> ep_url

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — Training pipeline → S3 → Model
    # ═══════════════════════════════════════════════════════════════════════════
    train >> Edge(label="save model.pkl")       >> s3
    s3    >> Edge(label="load model.pkl",
                  color="darkgreen",
                  style="bold")                >> model

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — URL prediction flow
    # ═══════════════════════════════════════════════════════════════════════════
    user   >> Edge(label="URL / UI request")   >> ep_web
    ep_web >> ep_url
    ep_url >> Edge(label="validate URL")       >> ssrf
    ssrf   >> fe_str
    ssrf   >> fe_http
    ssrf   >> fe_dns
    ssrf   >> fe_ext
    fe_str  >> Edge(label="30-feature\nvector") >> model
    fe_http >> model
    fe_dns  >> model
    fe_ext  >> model

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — CSV prediction flow
    # ═══════════════════════════════════════════════════════════════════════════
    user   >> Edge(label="CSV file")            >> ep_csv
    ep_csv >> Edge(label="pre-extracted\nfeatures") >> model

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — Model response to user
    # ═══════════════════════════════════════════════════════════════════════════
    model >> Edge(
        label="JSON Response\nprediction · confidence\n30 features · warnings"
    ) >> user

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — Feature Extractor → External APIs (no connections to User)
    # ═══════════════════════════════════════════════════════════════════════════
    fe_ext >> Edge(style="dashed",
                   label="threat intelligence") >> gsb
    fe_ext >> Edge(style="dashed",
                   label="domain popularity\nrank") >> tranco

    # ═══════════════════════════════════════════════════════════════════════════
    # Edges — FastAPI → MongoDB (app data / logs)
    # ═══════════════════════════════════════════════════════════════════════════
    ep_url >> Edge(style="dashed",
                   label="prediction logs /\napp data") >> mongo

print(f"Diagrama gerado: {OUTPUT}.png")
