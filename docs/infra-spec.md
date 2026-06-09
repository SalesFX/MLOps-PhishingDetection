# Infra Spec — Network Security MLOps (AWS + Terraform)
> Criado em: 2026-06-08  
> Status: aprovado pelo usuário  
> Escopo: infraestrutura AWS via Terraform para suportar CI/CD do projeto de detecção de phishing

---

## 1. Contexto

A plataforma MLOps de detecção de phishing tem os seguintes componentes de infra:

| Componente | Tecnologia | Onde vive |
|-----------|-----------|-----------|
| Banco de dados | MongoDB Atlas | Externo — **fora do escopo do Terraform** |
| Artefatos e modelos | S3 | AWS — provisionado aqui |
| Imagem Docker | ECR | AWS — provisionado aqui |
| Servidor de aplicação | EC2 + Docker | AWS — provisionado aqui |
| CI/CD | GitHub Actions | GitHub-hosted runners |

O Terraform gerencia **exclusivamente** S3, ECR, IAM/OIDC e EC2. Nada mais.

---

## 2. Decisões de design

| Decisão | Escolha | Motivo |
|---------|---------|--------|
| Terraform state | S3 remoto + DynamoDB lock | Padrão de mercado; separado do bucket da aplicação |
| Autenticação GitHub → AWS | OIDC (sem chaves estáticas) | Sem `AWS_ACCESS_KEY_ID`/`SECRET` em secrets; mais seguro |
| Runner de CI/CD | GitHub-hosted (`ubuntu-latest`) | EC2 não é self-hosted runner; deploy via SSH |
| Estrutura de stacks | 4 stacks por domínio | Ciclo de vida independente por responsabilidade |
| Key pair EC2 | Variável `key_name` (existente na AWS) | Chave privada não entra no state do Terraform |
| MongoDB | Externo (Atlas) | Não gerenciado; `MONGO_DB_URL` injetado pelo workflow |

---

## 3. Estrutura de arquivos

```
infra/
├── 00-remote-backend/
│   ├── main.tf                    # S3 tfstate bucket + DynamoDB lock table
│   ├── outputs.tf
│   └── providers.tf
│
├── 01-storage-registry/
│   ├── backend.tf                 # remote state no S3 (00)
│   ├── providers.tf
│   ├── variables.tf
│   ├── main.tf                    # S3 artifacts bucket + ECR repository
│   ├── outputs.tf
│   └── terraform.tfvars.example
│
├── 02-iam-oidc/
│   ├── backend.tf
│   ├── providers.tf
│   ├── variables.tf
│   ├── main.tf                    # OIDC provider + GitHub Actions IAM Role
│   ├── outputs.tf
│   └── terraform.tfvars.example
│
└── 03-compute/
    ├── backend.tf
    ├── providers.tf
    ├── variables.tf
    ├── main.tf                    # EC2 instance
    ├── security_group.tf          # portas 22 (ssh) e 8080 (app)
    ├── iam.tf                     # EC2 role + instance profile
    ├── outputs.tf
    ├── user_data.sh               # instala Docker apenas
    └── terraform.tfvars.example
```

---

## 4. Stack 00 — Remote Backend

### Responsabilidade
Bootstrap da infra Terraform. Aplicado uma única vez. State fica **local** (não usa backend remoto).

### Recursos
| Recurso Terraform | Nome AWS | Configuração |
|------------------|----------|--------------|
| `aws_s3_bucket` | `network-security-mlops-tfstate-<account_id>` | Nome único via `data.aws_caller_identity` |
| `aws_s3_bucket_versioning` | — | `ENABLED` |
| `aws_s3_bucket_server_side_encryption_configuration` | — | SSE-S3 (AES256) |
| `aws_s3_bucket_public_access_block` | — | Tudo bloqueado |
| `aws_dynamodb_table` | `network-security-mlops-tfstate-lock` | PAY_PER_REQUEST, hash_key = `"LockID"` |

### Variáveis
| Variável | Default |
|----------|---------|
| `aws_region` | `"us-east-1"` |
| `project_name` | `"network-security-mlops"` |

### Outputs
| Output | Valor |
|--------|-------|
| `tfstate_bucket_name` | nome do bucket criado |
| `tfstate_dynamodb_table_name` | nome da tabela criada |

---

## 5. Stack 01 — Storage + Registry

### Responsabilidade
Armazenamento de artefatos/modelos (S3) e repositório de imagem Docker (ECR).

### Recursos
| Recurso Terraform | Nome AWS | Configuração |
|------------------|----------|--------------|
| `aws_s3_bucket` | `demo-networksecurity-<account_id>` | Ver nota abaixo |
| `aws_s3_bucket_versioning` | — | `ENABLED` |
| `aws_s3_bucket_server_side_encryption_configuration` | — | SSE-S3 |
| `aws_s3_bucket_public_access_block` | — | Tudo bloqueado |
| `aws_ecr_repository` | `network-security` | `image_tag_mutability = "MUTABLE"`, scan on push |
| `aws_ecr_lifecycle_policy` | — | Expira `untagged` após 1 dia; mantém últimas 10 tagged |

> **Nota sobre nome do bucket S3:**  
> O código da aplicação tem `TRAINING_BUCKET_NAME = "demo-networksecurity"` hardcoded em  
> `network_security/constant/training_pipeline/__init__.py`.  
> O bucket será criado com sufixo `<account_id>` para garantir unicidade global.  
> **Ajuste obrigatório da aplicação** antes do deploy final: remover o hardcode e ler de  
> `os.getenv("AWS_S3_BUCKET_NAME")`. O valor da variável de ambiente será o nome real do  
> bucket criado por este stack. Este ajuste **não faz parte do escopo Terraform** — é uma  
> tarefa separada na aplicação.

### Variáveis
| Variável | Default | Descrição |
|----------|---------|-----------|
| `aws_region` | `"us-east-1"` | |
| `project_name` | `"network-security-mlops"` | |
| `environment` | `"production"` | |
| `tfstate_bucket` | — | Nome do bucket do `00` |

### Outputs
| Output | Descrição |
|--------|-----------|
| `app_bucket_name` | Nome real do bucket S3 |
| `app_bucket_arn` | ARN para uso em policies |
| `ecr_repository_name` | `network-security` |
| `ecr_repository_url` | `<account>.dkr.ecr.<region>.amazonaws.com/network-security` (URL completa) |
| `ecr_registry` | `<account>.dkr.ecr.<region>.amazonaws.com` (somente o registry, sem o nome do repo) |
| `ecr_repository_arn` | ARN para uso em policies |

> **Padronização ECR:** o workflow usa dois secrets separados — `ECR_REGISTRY` (só o host)  
> e `ECR_REPOSITORY_NAME` (só o nome do repo). O output `ecr_registry` alimenta o secret  
> `ECR_REGISTRY`; o output `ecr_repository_name` alimenta `ECR_REPOSITORY_NAME`.  
> O `ecr_repository_url` (URL completa) é conveniente para exibir no terminal mas não vira secret.

---

## 6. Stack 02 — IAM + OIDC

### Responsabilidade
Permite que o GitHub Actions assuma uma IAM Role via token OIDC federado — sem chaves estáticas.

### Recursos
| Recurso Terraform | Descrição |
|------------------|-----------|
| `aws_iam_openid_connect_provider` | Provider `token.actions.githubusercontent.com`. Thumbprint fixo do GitHub. Se já existir na conta, usar `data` source + `import`. |
| `aws_iam_role` (`github_actions`) | Trust policy restrita a `repo:<owner>/<repo>:ref:refs/heads/<branch>` |
| `aws_iam_policy` (`github_actions`) | Permissões mínimas (ver abaixo) |
| `aws_iam_role_policy_attachment` | Anexa policy à role |
| `data.terraform_remote_state.storage` | Consome ARNs do `01` para construir policies com ARNs exatos |

### Permissões da GitHub Actions Role
```
ECR:
  ecr:GetAuthorizationToken              (recurso: *)
  ecr:BatchCheckLayerAvailability        (recurso: ecr_repository_arn)
  ecr:GetDownloadUrlForLayer             (recurso: ecr_repository_arn)
  ecr:BatchGetImage                      (recurso: ecr_repository_arn)
  ecr:InitiateLayerUpload                (recurso: ecr_repository_arn)
  ecr:UploadLayerPart                    (recurso: ecr_repository_arn)
  ecr:CompleteLayerUpload                (recurso: ecr_repository_arn)
  ecr:PutImage                           (recurso: ecr_repository_arn)

S3 (para sync de artefatos no pipeline, se necessário):
  s3:PutObject                           (recurso: app_bucket_arn/*)
  s3:GetObject                           (recurso: app_bucket_arn/*)
  s3:DeleteObject                        (recurso: app_bucket_arn/*)
  s3:ListBucket                          (recurso: app_bucket_arn)
```

### Variáveis
| Variável | Default | Descrição |
|----------|---------|-----------|
| `aws_region` | `"us-east-1"` | |
| `project_name` | `"network-security-mlops"` | |
| `environment` | `"production"` | |
| `github_owner` | — | Ex: `"SalesFX"` |
| `github_repo` | — | Ex: `"MLOps-NetworkSecurity"` |
| `github_branch` | `"main"` | |
| `tfstate_bucket` | — | |

### Outputs
| Output | Descrição |
|--------|-----------|
| `github_actions_role_arn` | ARN a ser copiado para GitHub Secret `AWS_ROLE_ARN` |

---

## 7. Stack 03 — Compute

### Responsabilidade
EC2 com Docker instalado. Serve a aplicação. **Não é self-hosted runner do GitHub Actions.**  
O deploy é feito via SSH pelo GitHub Actions a partir de runner `ubuntu-latest`.

### Recursos

**`main.tf`**
| Recurso Terraform | Configuração |
|------------------|--------------|
| `data.aws_ami` | Amazon Linux 2023 latest via SSM `/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64` |
| `aws_instance` | `t3.medium`, `key_name = var.key_name`, instance profile, `http_tokens = "required"` (IMDSv2), root volume 20 GB gp3, `user_data = user_data.sh` |

**`security_group.tf`**
| Regra | Porta | Origem |
|-------|-------|--------|
| Ingress SSH | 22 | `var.allowed_ssh_cidr` (obrigatório, sem default) |
| Ingress App | 8080 | `var.allowed_app_cidr` (default: `"0.0.0.0/0"`) |
| Egress | tudo | `0.0.0.0/0` |

**`iam.tf`**
| Recurso Terraform | Descrição |
|------------------|-----------|
| `aws_iam_role` (`ec2`) | Trust policy para `ec2.amazonaws.com` |
| `aws_iam_instance_profile` | Anexado à instância |
| `aws_iam_policy` (`ec2`) | ECR pull + S3 read/write (ARNs via `terraform_remote_state`) |
| `aws_iam_role_policy_attachment` | |

**Permissões da EC2 Role (instance profile):**
```
ECR:
  ecr:GetAuthorizationToken              (recurso: *)
  ecr:BatchCheckLayerAvailability        (recurso: ecr_repository_arn)
  ecr:GetDownloadUrlForLayer             (recurso: ecr_repository_arn)
  ecr:BatchGetImage                      (recurso: ecr_repository_arn)

S3 (para sync de artefatos da aplicação em runtime):
  s3:PutObject                           (recurso: app_bucket_arn/*)
  s3:GetObject                           (recurso: app_bucket_arn/*)
  s3:DeleteObject                        (recurso: app_bucket_arn/*)
  s3:ListBucket                          (recurso: app_bucket_arn)
```

**`user_data.sh`**
```bash
#!/bin/bash
dnf update -y
dnf install -y docker awscli
systemctl enable docker
systemctl start docker
usermod -aG docker ec2-user
mkdir -p /app
chown ec2-user:ec2-user /app
```

Nenhum secret, nenhuma credencial, nenhum token de runner neste script.

> `awscli` é necessário para que o `ec2-user` possa executar `aws ecr get-login-password`  
> antes do `docker pull` durante o deploy via SSH.

### Variáveis
| Variável | Default | Descrição |
|----------|---------|-----------|
| `aws_region` | `"us-east-1"` | |
| `project_name` | `"network-security-mlops"` | |
| `environment` | `"production"` | |
| `instance_type` | `"t3.medium"` | |
| `key_name` | — | Nome do key pair **já existente** na AWS |
| `allowed_ssh_cidr` | — | **Sem default. Obrigatório. Use `SEU_IP/32`.** |
| `allowed_app_cidr` | `"0.0.0.0/0"` | |
| `tfstate_bucket` | — | |

### Outputs
| Output | Descrição |
|--------|-----------|
| `ec2_public_ip` | IP para GitHub Secret `EC2_HOST` |
| `ec2_public_dns` | DNS público |
| `security_group_id` | ID do security group |
| `instance_id` | ID da instância EC2 |

---

## 8. Conexões entre stacks

```
00-remote-backend
  └─► outputs manuais: tfstate_bucket_name, tfstate_dynamodb_table_name
        └─► copiados para backend.tf de 01, 02 e 03

01-storage-registry
  └─► remote state key: "01-storage-registry/terraform.tfstate"
        └─► consumido por 02-iam-oidc  via data.terraform_remote_state
        └─► consumido por 03-compute   via data.terraform_remote_state

02-iam-oidc
  └─► output manual: github_actions_role_arn
        └─► GitHub Secret: AWS_ROLE_ARN

03-compute
  └─► output manual: ec2_public_ip
        └─► GitHub Secret: EC2_HOST
```

---

## 9. GitHub Secrets — estado final esperado

| Secret | Origem | Observação |
|--------|--------|------------|
| `AWS_ROLE_ARN` | output `02-iam-oidc` | **Novo** — substitui as chaves estáticas |
| `AWS_REGION` | fixo `us-east-1` | Já existe |
| `ECR_REGISTRY` | `<account>.dkr.ecr.us-east-1.amazonaws.com` | **Novo** — substitui `AWS_ECR_LOGIN_URI` |
| `ECR_REPOSITORY_NAME` | output `01` (`ecr_repository_name`) | Já existe (atualizar valor) |
| `AWS_S3_BUCKET_NAME` | output `01` (`app_bucket_name`) | **Novo** — injetado no `docker run` |
| `EC2_HOST` | output `03` (`ec2_public_ip`) | **Novo** — para SSH no deploy |
| `EC2_SSH_PRIVATE_KEY` | arquivo `.pem` local | **Novo** — chave privada do key pair |
| `MONGO_DB_URL` | MongoDB Atlas | Já existe. **Nunca toca no Terraform.** |
| ~~`AWS_ACCESS_KEY_ID`~~ | — | **Removido** (substituído por OIDC) |
| ~~`AWS_SECRET_ACCESS_KEY`~~ | — | **Removido** (substituído por OIDC) |
| ~~`AWS_ECR_LOGIN_URI`~~ | — | **Removido** — substituído por `ECR_REGISTRY` |

---

## 10. Ajustes obrigatórios fora do Terraform

### 10.1 Aplicação — `TRAINING_BUCKET_NAME` hardcoded

**Arquivo:** `network_security/constant/training_pipeline/__init__.py`  
**Linha atual:** `TRAINING_BUCKET_NAME = "demo-networksecurity"`  
**Ajuste:** trocar para `TRAINING_BUCKET_NAME = os.getenv("AWS_S3_BUCKET_NAME", "demo-networksecurity")`  
**Quando:** antes do primeiro deploy em produção (após aplicar o `01-storage-registry`)  
**Impacto:** sem esse ajuste, a aplicação tentará usar o bucket errado em produção

### 10.2 Workflow — `.github/workflows/main.yaml`

Mudanças obrigatórias quando a infra estiver provisionada:

| Job | Mudança |
|----|---------|
| `build-and-push-ecr-image` | `configure-aws-credentials@v1` → `@v4` com `role-to-assume: ${{ secrets.AWS_ROLE_ARN }}` |
| `Continuous-Deployment` | `runs-on: self-hosted` → `ubuntu-latest` |
| `Continuous-Deployment` | Steps de deploy via SSH (`appleboy/ssh-action`) |
| `Continuous-Deployment` | Script SSH deve executar docker login via instance profile antes do pull: `aws ecr get-login-password --region $AWS_REGION \| docker login --username AWS --password-stdin $ECR_REGISTRY` |
| `Continuous-Deployment` | Remover `-e AWS_ACCESS_KEY_ID` e `-e AWS_SECRET_ACCESS_KEY` do `docker run` |
| `Continuous-Deployment` | `docker run` deve injetar: `-e "MONGO_DB_URL=..."` e `-e "AWS_S3_BUCKET_NAME=..."` |
| `Continuous-Deployment` | Descomentar o step `docker stop` |
| Ambos | `echo "::set-output"` → `echo "..." >> $GITHUB_OUTPUT` |
| Ambos | `actions/checkout@v3` → `@v4` |
| Ambos | `aws-actions/configure-aws-credentials@v1` → `@v4` |
| Ambos | Usar `ECR_REGISTRY` (substitui `AWS_ECR_LOGIN_URI`) |

---

## 11. Ordem de aplicação

```
Passo 1: Criar key pair na AWS (manualmente, fora do Terraform)
  aws ec2 create-key-pair \
    --key-name network-security-mlops \
    --query 'KeyMaterial' \
    --output text > ~/.ssh/network-security-mlops.pem
  chmod 400 ~/.ssh/network-security-mlops.pem

Passo 2: cd infra/00-remote-backend
  terraform init
  terraform apply
  → anote tfstate_bucket_name

Passo 3: Preencha backend.tf de 01, 02 e 03 com o bucket name

Passo 4: cd infra/01-storage-registry
  terraform init && terraform apply
  → anote ecr_repository_url e app_bucket_name

Passo 5: cd infra/02-iam-oidc
  terraform init && terraform apply
  → copie github_actions_role_arn → GitHub Secret AWS_ROLE_ARN

Passo 6: cd infra/03-compute
  terraform init && terraform apply
  → copie ec2_public_ip → GitHub Secret EC2_HOST

Passo 7: Adicionar GitHub Secrets EC2_SSH_PRIVATE_KEY, AWS_ROLE_ARN, EC2_HOST

Passo 8: Atualizar TRAINING_BUCKET_NAME no app (seção 10.1)

Passo 9: Atualizar workflow (seção 10.2)
```

---

## 12. Riscos e pontos de atenção

| Risco | Mitigação |
|-------|-----------|
| OIDC provider já existe na conta AWS | Verificar antes: `aws iam list-open-id-connect-providers`. Se existir, usar `data` source e `terraform import` |
| `allowed_ssh_cidr` sem default | Intencional — força o usuário a especificar o IP. `.tfvars.example` tem `"SEU_IP/32"` como placeholder |
| Key pair deve existir antes do `03` apply | Criar manualmente (Passo 1 acima) |
| `TRAINING_BUCKET_NAME` hardcoded | Ajustar app antes do deploy (seção 10.1) |
| `docker stop` comentado no workflow | Descomentar no ajuste do workflow (seção 10.2) |
| IMDSv2 obrigatório (`http_tokens = "required"`) | boto3 >= 1.9 e AWS CLI >= 1.16 já suportam IMDSv2 |

---

## 13. Fora do escopo (confirmação explícita)

| Item | Status |
|------|--------|
| GitHub PAT no Terraform | Ausente |
| Self-hosted runner na EC2 | Ausente |
| MongoDB na AWS | Ausente — Atlas é externo |
| `MONGO_DB_URL` no Terraform | Ausente — injetado pelo workflow |
| EKS / Kubernetes | Ausente |
| Observabilidade (CloudWatch alarms, Prometheus, Grafana) | Ausente |
| RDS / DocumentDB | Ausente |
| Secrets hardcoded em qualquer `.tf` | Ausente |
