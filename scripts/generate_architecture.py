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
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "1.0",
    "splines": "curved",
    "nodesep": "0.6",
    "ranksep": "0.9",
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
    github = Github("GitHub\nMLOps-PhishingDetection")

    with Cluster("CI/CD — GitHub Actions"):
        ci = GithubActions("pytest 151 tests\ndocker build + push ECR\nSSH deploy to EC2")

    with Cluster("AWS — Terraform"):
        oidc = General("IAM / OIDC")
        ecr  = General("ECR\nDocker registry")
        ec2  = EC2("EC2 t3.small")
        s3   = S3("S3\nmodel.pkl")

    with Cluster("Docker Container — FastAPI"):
        api = FastAPI(
            "POST /predict-url  (URL mode)\n"
            "POST /predict       (CSV mode)\n"
            "GET  /url-checker   (UI)\n"
            "GET  /train         (pipeline)"
        )
        fe = Python(
            "Feature Extractor — 30 features\n"
            "String · HTTP/HTML · DNS/WHOIS\n"
            "External APIs · SSRF Validator"
        )
        model = Python("Gradient Boosting\nF1=0.97 · Recall=0.97")

    with Cluster("External Services"):
        mongo  = MongoDB("MongoDB Atlas")
        gsb    = General("Google Safe Browsing\nStatistical_report")
        tranco = General("Tranco API\nweb_traffic")

    user = User("User / Browser")
    resp = Python("JSON Response\nprediction · confidence\n30 features · warnings")

    # main flows
    github >> Edge(label="push") >> ci
    oidc   >> Edge(style="dashed") >> ci
    ci     >> Edge(label="push image") >> ecr
    ci     >> Edge(label="SSH deploy") >> ec2
    ec2    >> api

    s3    >> Edge(label="load model.pkl", color="darkgreen") >> model
    api   >> Edge(label="save artifacts", style="dashed") >> s3

    user  >> Edge(label="URL / CSV") >> api
    api   >> fe
    fe    >> Edge(label="30-feature vector") >> model
    model >> resp
    resp  >> Edge(label="JSON") >> user

    fe >> Edge(style="dashed") >> gsb
    fe >> Edge(style="dashed") >> tranco
    fe >> Edge(style="dashed", label="DNS / WHOIS / data") >> mongo


print(f"Diagrama gerado: {OUTPUT}.png")
