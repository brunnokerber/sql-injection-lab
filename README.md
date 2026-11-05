# Laboratório Prático de SQL Injection (SQLi)

Projeto desenvolvido para o Trabalho Final da disciplina de **Segurança e Auditoria de Sistemas** (Feevale).

O objetivo da aplicação é demonstrar, de forma prática e comparativa, como vulnerabilidades de **SQL Injection (CWE-89 / OWASP A03:2021 - Injection)** ocorrem em aplicações Web e como mitigá-las utilizando **Consultas Parametrizadas (Prepared Statements)** e validação de entrada.

---

## 🏗️ Arquitetura e Comparativo de Rotas

A aplicação foi construída em **Python + Flask + SQLite** e possui **duas rotas espelhadas** para cada funcionalidade (Autenticação, Listagem/Filtro de Produtos e Inserção de Produtos), acompanhadas de um **Monitor de Auditoria SQL em Tempo Real** na interface:

| Funcionalidade | Rota Vulnerável (Sem Proteção) | Rota Segura (Mitigada) |
| :--- | :--- | :--- |
| **Autenticação (Login)** | `GET/POST /vuln/login`<br>Concatenação direta com `f-string` | `GET/POST /seguro/login`<br>Prepared Statement (`?`) |
| **Listagem e Filtro de Produtos** | `GET /vuln/produtos?filtro=...`<br>Interpolação direta em `LIKE '%...%'` | `GET /seguro/produtos?filtro=...`<br>Placeholder parametrizado `LIKE ?` |
| **Cadastro de Produto** | `POST /vuln/produtos/novo`<br>`f-string` + `cursor.executescript()` | `POST /seguro/produtos/novo`<br>Validação de tipo (`float`) + `cursor.execute()` parametrizado |

---

## 🛡️ Relação com os Pilares da Segurança da Informação (Tríade CIA)

1. **Autenticidade (Bypass de Login em `/vuln/login`)**:
   - **Ataque**: Uso de `' OR '1'='1' --` ou `admin' --` permite autenticar como administrador sem conhecer a senha.
2. **Confidencialidade (Exfiltração de Dados em `/vuln/produtos`)**:
   - **Ataque**: Uso de `' OR 1=1 --` exibe produtos restritos (`visivel = 0`), e `' UNION SELECT id, username, password, role FROM usuarios --` vaza todas as credenciais do banco na tabela de produtos.
3. **Integridade e Disponibilidade (Stacked Queries em `/vuln/produtos/novo`)**:
   - **Ataque**: Injeção no campo de descrição (`Item'); UPDATE produtos SET valor = 0.01; --` ou `DELETE FROM produtos; --`) altera preços ou apaga registros do catálogo.

---

## 🚀 Como Executar o Projeto

### 1. Criar e ativar o ambiente virtual (opcional, recomendado)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Instalar as dependências
```powershell
pip install -r requirements.txt
```

### 3. Iniciar o servidor Flask
```powershell
python app.py
```

Acesse no navegador: **http://127.0.0.1:5000**

---

## 🧪 Guia Rápido de Payloads para Apresentação

A própria interface possui botões de **Preenchimento Rápido (1-Click)** para testar os cenários abaixo tanto no modo **Vulnerável (`/vuln`)** quanto no modo **Seguro (`/seguro`)**:

### 1. Autenticação (`/vuln/login` vs `/seguro/login`)
- **Bypass de Administrador (Comentário SQL)**:
  - **Usuário**: `admin' --`
  - **Senha**: `qualquer_coisa`
- **Bypass por Tautologia**:
  - **Usuário**: `' OR '1'='1' --`
  - **Senha**: `123`

### 2. Filtro de Produtos (`/vuln/produtos` vs `/seguro/produtos`)
- **Exibir Produto Oculto (`visivel = 0`)**:
  - **Filtro**: `' OR 1=1 --`
- **Vazar Tabela de Usuários (`UNION SELECT`)**:
  - **Filtro**: `' UNION SELECT id, username, password, role FROM usuarios --`
- **Mapear Tabelas do Banco (`sqlite_master`)**:
  - **Filtro**: `' UNION SELECT 1, name, type, sql FROM sqlite_master WHERE type='table' --`

### 3. Inserção de Produtos (`/vuln/produtos/novo` vs `/seguro/produtos/novo`)
- **Adulterar Preços (Violação de Integridade)**:
  - **Nome**: `Cabo Cat6` | **Valor**: `25.00`
  - **Descrição**: `Item'); UPDATE produtos SET valor = 0.01; --`
- **Criar Conta Admin Backdoor**:
  - **Nome**: `Mouse USB` | **Valor**: `40.00`
  - **Descrição**: `Normal'); INSERT INTO usuarios (username, password, role) VALUES ('hacker', 'pwned', 'admin'); --`

> 💡 **Dica**: A qualquer momento durante a demonstração, clique no botão **"🔄 Resetar Banco"** no topo da página para restaurar todas as tabelas e registros originais!
