"""Gera o diagrama de arquitetura do projeto MLOps Phishing Detection."""

from pathlib import Path

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import EC2
from diagrams.aws.storage import S3
from diagrams.aws.general import General
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.container import Docker
from diagrams.onprem.database import MongoDB
from diagrams.onprem.vcs import Github
from diagrams.programming.language import Python
from diagrams.programming.framework import FastAPI

OUTPUT = str(Path(__file__).parent.parent / "images" / "architecture")

graph_attr = {
    "fontsize": "12",
    "bgcolor": "white",
    "pad": "0.8",
    "splines": "ortho",
    "nodesep": "0.6",
    "ranksep": "0.8",
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
        ci  = GithubActions("1. Integration\npytest 151 tests")
        cd  = GithubActions("2. Delivery\ndocker build + push")
        dep = GithubActions("3. Deployment\nSSH → EC2")

    with Cluster("AWS — Terraform (4 stacks)"):
        oidc = General("IAM / OIDC")
        ecr  = General("ECR")
        s3   = S3("S3\nArtifacts")
        ec2  = EC2("EC2 t3.small")

    with Cluster("Docker Container — FastAPI"):
        api      = Python("POST /predict-url\nGET  /url-checker\nGET  /train")
        extrator = Python("Feature Extractor\n30 features")
        model    = Python("Gradient Boosting\n(scikit-learn)")

    mongo  = MongoDB("MongoDB Atlas")
    tranco = General("Tranco API")
    gsb    = General("Google Safe\nBrowsing API")

    # main flow
    github >> ci >> cd >> dep

    cd  >> Edge(label="push image") >> ecr
    dep >> Edge(label="pull & run") >> ec2
    ec2 >> api

    # model uses
    api      >> extrator
    api      >> model
    model    >> Edge(label="load .pkl") >> s3

    # extractor uses
    extrator >> Edge(style="dashed") >> mongo
    extrator >> Edge(style="dashed") >> tranco
    extrator >> Edge(style="dashed") >> gsb

    # training
    api >> Edge(label="train") >> mongo

    # OIDC
    oidc >> Edge(style="dashed", label="auth") >> cd


print(f"Diagrama gerado: {OUTPUT}.png")
