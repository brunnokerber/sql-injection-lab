from flask import Flask, flash, redirect, render_template, request, session, url_for
from database import get_db_connection, init_db

app = Flask(__name__)
app.secret_key = "chave-secreta-academica-feevale-seguranca"

# Inicializa o banco na subida da aplicacao
init_db()


def registrar_auditoria_sql(modo, operacao, query, params=None, erro=None):
    """Armazena na sessao a ultima query executada para exibicao didatica na UI."""
    session["sql_audit"] = {
        "modo": modo,
        "operacao": operacao,
        "query": query,
        "params": repr(params) if params is not None else None,
        "erro": str(erro) if erro else None,
    }


@app.route("/")
def index():
    return redirect(url_for("vuln_login"))


@app.route("/logout")
def logout():
    modo_atual = request.args.get("modo", "vuln")
    session.clear()
    flash("Sessão encerrada com sucesso.", "info")
    if modo_atual == "seguro":
        return redirect(url_for("seguro_login"))
    return redirect(url_for("vuln_login"))


@app.route("/reset-db", methods=["POST"])
def reset_db():
    init_db(force_reset=True)
    flash("Banco de dados restaurado para o estado inicial (Seed)!", "success")
    next_url = request.form.get("next") or url_for("vuln_login")
    return redirect(next_url)


# ==============================================================================
# ROTAS VULNERAVEIS (/vuln/...) - SEM PROTECAO CONTRA SQL INJECTION
# ==============================================================================


@app.route("/vuln/login", methods=["GET", "POST"])
def vuln_login():
    erro = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILidade: Concatenacao direta de strings (f-string) na consulta SQL
        query = (
            f"SELECT id, username, role FROM usuarios "
            f"WHERE username = '{username}' AND password = '{password}'"
        )

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query)
            user = cursor.fetchone()
            registrar_auditoria_sql("vuln", "Autenticação (Login)", query)

            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                flash(
                    f"Login realizado no modo VULNERÁVEL como '{user['username']}' (perfil: {user['role']}).",
                    "success",
                )
                return redirect(url_for("vuln_produtos"))
            else:
                erro = "Credenciais inválidas."
        except Exception as e:
            erro = f"Erro de Banco de Dados (SQLite): {e}"
            registrar_auditoria_sql("vuln", "Autenticação (Login)", query, erro=e)
        finally:
            conn.close()

    return render_template("login.html", modo="vuln", erro=erro)


@app.route("/vuln/produtos", methods=["GET"])
def vuln_produtos():
    filtro = request.args.get("filtro", "")
    produtos = []
    erro = None

    # VULNERABILIDADE: Interpolacao direta do parametro de busca na clausula LIKE
    query = (
        f"SELECT id, nome, valor, descricao FROM produtos "
        f"WHERE visivel = 1 AND nome LIKE '%{filtro}%'"
    )

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        produtos = cursor.fetchall()
        # So sobrescreve o painel de auditoria se houve filtro ou se nao veio de um POST recente
        if filtro or "sql_audit" not in session:
            registrar_auditoria_sql("vuln", "Listagem / Filtro de Produtos", query)
    except Exception as e:
        erro = f"Erro de Banco de Dados (SQLite): {e}"
        registrar_auditoria_sql("vuln", "Listagem / Filtro de Produtos", query, erro=e)
    finally:
        conn.close()

    return render_template(
        "produtos.html",
        modo="vuln",
        produtos=produtos,
        filtro=filtro,
        erro=erro,
    )


@app.route("/vuln/produtos/novo", methods=["POST"])
def vuln_novo_produto():
    nome = request.form.get("nome", "")
    valor = request.form.get("valor", "0")
    descricao = request.form.get("descricao", "")

    # VULNERABILIDADE: Concatenacao direta + uso de executescript (permite Stacked Queries!)
    query = (
        f"INSERT INTO produtos (nome, valor, descricao) "
        f"VALUES ('{nome}', {valor}, '{descricao}');"
    )

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.executescript(query)
        conn.commit()
        registrar_auditoria_sql("vuln", "Inserção de Produto (executescript)", query)
        flash("Comando de inserção executado no modo VULNERÁVEL!", "success")
    except Exception as e:
        conn.rollback()
        registrar_auditoria_sql(
            "vuln", "Inserção de Produto (executescript)", query, erro=e
        )
        flash(f"Erro SQL ao inserir produto: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for("vuln_produtos"))


# ==============================================================================
# ROTAS SEGURAS (/seguro/...) - COM PROTECAO CONTRA SQL INJECTION
# ==============================================================================


@app.route("/seguro/login", methods=["GET", "POST"])
def seguro_login():
    erro = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # MITIGACAO: Uso de Prepared Statements / Consultas Parametrizadas (?)
        query = (
            "SELECT id, username, role FROM usuarios "
            "WHERE username = ? AND password = ?"
        )
        params = (username, password)

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            user = cursor.fetchone()
            registrar_auditoria_sql("seguro", "Autenticação Parametrizada", query, params)

            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                flash(
                    f"Login realizado no modo SEGURO como '{user['username']}' (perfil: {user['role']}).",
                    "success",
                )
                return redirect(url_for("seguro_produtos"))
            else:
                erro = "Credenciais inválidas."
        except Exception as e:
            erro = "Ocorreu um erro interno ao processar a autenticação."
            registrar_auditoria_sql(
                "seguro", "Autenticação Parametrizada", query, params, erro=e
            )
        finally:
            conn.close()

    return render_template("login.html", modo="seguro", erro=erro)


@app.route("/seguro/produtos", methods=["GET"])
def seguro_produtos():
    filtro = request.args.get("filtro", "")
    produtos = []
    erro = None

    # MITIGACAO: Parametro vinculado via placeholder (?)
    query = (
        "SELECT id, nome, valor, descricao FROM produtos "
        "WHERE visivel = 1 AND nome LIKE ?"
    )
    params = (f"%{filtro}%",)

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        produtos = cursor.fetchall()
        if filtro or "sql_audit" not in session:
            registrar_auditoria_sql(
                "seguro", "Listagem / Filtro Parametrizado", query, params
            )
    except Exception as e:
        erro = "Erro ao consultar produtos."
        registrar_auditoria_sql(
            "seguro", "Listagem / Filtro Parametrizado", query, params, erro=e
        )
    finally:
        conn.close()

    return render_template(
        "produtos.html",
        modo="seguro",
        produtos=produtos,
        filtro=filtro,
        erro=erro,
    )


@app.route("/seguro/produtos/novo", methods=["POST"])
def seguro_novo_produto():
    nome = request.form.get("nome", "").strip()
    valor_raw = request.form.get("valor", "0").strip()
    descricao = request.form.get("descricao", "").strip()

    # MITIGACAO 1: Validacao estrita de tipos e campos no backend
    try:
        valor = float(valor_raw)
    except ValueError:
        flash("Valor inválido: informe apenas números (ex: 199.90).", "danger")
        return redirect(url_for("seguro_produtos"))

    if not nome or not descricao:
        flash("Nome e descrição são obrigatórios.", "danger")
        return redirect(url_for("seguro_produtos"))

    # MITIGACAO 2: Uso de cursor.execute() parametrizado (bloqueia multiplas queries e trata dados como literais)
    query = "INSERT INTO produtos (nome, valor, descricao) VALUES (?, ?, ?)"
    params = (nome, valor, descricao)

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        registrar_auditoria_sql("seguro", "Inserção Parametrizada", query, params)
        flash("Produto cadastrado com segurança no modo SEGURO!", "success")
    except Exception as e:
        conn.rollback()
        registrar_auditoria_sql(
            "seguro", "Inserção Parametrizada", query, params, erro=e
        )
        flash("Erro ao cadastrar produto.", "danger")
    finally:
        conn.close()

    return redirect(url_for("seguro_produtos"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
