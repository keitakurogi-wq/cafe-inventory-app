from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from functools import wraps
import sqlite3
import os
import re
import secrets

app = Flask(__name__)

# flash() を使うために必要な秘密鍵
# 本番（Render）では環境変数 SECRET_KEY を設定する
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

# 日本時間（Renderのサーバーは UTC のため明示する）
JST = timezone(timedelta(hours=9))

# デモ用の初期パスワード（パスワード未設定の従業員に設定される）
# ログイン後、店長がマスタ管理から変更できる
DEFAULT_PASSWORD = "password"

# 入力値の上限（バリデーション用）
MAX_NUMBER = 99999        # 数量・在庫の上限
MAX_ID_LENGTH = 10        # 商品ID・従業員ID
MAX_NAME_LENGTH = 50      # 商品名・従業員名
MAX_UNIT_LENGTH = 10      # 単位
MAX_MEMO_LENGTH = 100     # メモ

# app.py が置いてあるフォルダ
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# SQLiteデータベース
DATABASE = os.path.join(BASE_DIR, "inventory.db")

# schema.sql
SCHEMA_FILE = os.path.join(BASE_DIR, "schema.sql")


def init_db():
    """
    inventory.db が存在しない場合だけ、
    schema.sql を読み込んでデータベースを作成する
    """
    if not os.path.exists(DATABASE):

        conn = sqlite3.connect(DATABASE)

        with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
            schema = f.read()

        conn.executescript(schema)
        conn.commit()
        conn.close()

        print("データベースを初期化しました。")

    # 既存DBに memo 列がなければ追加する（データは消さない）
    add_memo_column()

    # 既存DBにログイン用の列がなければ追加する
    add_login_columns()


def add_memo_column():
    """
    memo 列を後から追加したため、
    古い inventory.db には列が無い。その場合だけ ALTER TABLE で追加する。
    """
    conn = sqlite3.connect(DATABASE)

    columns = conn.execute("PRAGMA table_info(inventory_logs)").fetchall()
    column_names = [column[1] for column in columns]

    if "memo" not in column_names:
        conn.execute("ALTER TABLE inventory_logs ADD COLUMN memo TEXT")
        conn.commit()
        print("inventory_logs に memo 列を追加しました。")

    conn.close()


def add_login_columns():
    """
    employees に role（権限）と password_hash（パスワード）の列を追加する。
    ・role が無い古いDB → 列を追加し、E001 を店長にする
    ・パスワード未設定の従業員 → 初期パスワードを設定する
    """
    conn = sqlite3.connect(DATABASE)

    columns = conn.execute("PRAGMA table_info(employees)").fetchall()
    column_names = [column[1] for column in columns]

    if "role" not in column_names:
        conn.execute("ALTER TABLE employees ADD COLUMN role TEXT NOT NULL DEFAULT 'staff'")
        conn.execute("UPDATE employees SET role = 'manager' WHERE employee_id = 'E001'")
        print("employees に role 列を追加しました。")

    if "password_hash" not in column_names:
        conn.execute("ALTER TABLE employees ADD COLUMN password_hash TEXT")
        print("employees に password_hash 列を追加しました。")

    # パスワードはそのまま保存せず、ハッシュ化（元に戻せない形に変換）して保存する
    conn.execute(
        "UPDATE employees SET password_hash = ? WHERE password_hash IS NULL",
        (generate_password_hash(DEFAULT_PASSWORD),)
    )

    conn.commit()
    conn.close()


def get_db_connection():
    """
    SQLiteへ接続する共通処理
    """

    conn = sqlite3.connect(DATABASE)

    # product["product_name"] のように
    # 列名でデータを取得できるようにする
    conn.row_factory = sqlite3.Row

    return conn


# アプリ起動時にDB確認
init_db()


# =========================
# ログイン・権限チェック
# =========================

@app.before_request
def load_logged_in_user():
    """
    すべてのリクエストの前に実行される。
    ログイン中なら、従業員の情報をDBから読み込んで g.user に入れる。
    （毎回DBから読むので、権限を変更したらすぐ反映される）
    """
    employee_id = session.get("employee_id")

    g.user = None

    if employee_id:
        conn = get_db_connection()
        g.user = conn.execute(
            "SELECT employee_id, employee_name, role FROM employees WHERE employee_id = ?",
            (employee_id,)
        ).fetchone()
        conn.close()


# =========================
# CSRF対策
# 他のサイトから勝手にフォームを送信される攻撃を防ぐ。
# フォームに「合言葉（トークン）」を埋め込み、
# 送信されたトークンがセッションのものと一致するか確認する。
# =========================

def get_csrf_token():
    """
    セッションにトークンがなければ作成して返す。
    テンプレートで {{ csrf_token() }} として使う。
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


# すべてのテンプレートで csrf_token() を使えるようにする
app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def check_csrf_token():
    """
    POSTのときだけ、トークンが正しいか確認する。
    """
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            flash("画面の有効期限が切れました。もう一度操作してください。", "warning")
            # 元の画面（なければトップ）へ戻す
            return redirect(request.referrer or url_for("index"))


def is_valid_id(value):
    """
    IDが「英大文字と数字だけ・10文字以内」か確認する。
    例：P005、E004 → OK ／ P-01、あいう → NG
    """
    return re.fullmatch(r"[A-Z0-9]{1,%d}" % MAX_ID_LENGTH, value) is not None


def login_required(view):
    """
    ログインしていない人をログイン画面へ移動させるデコレーター。
    @login_required をルートの下に付けて使う。
    """
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            flash("ログインしてください。", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def manager_required(view):
    """
    店長だけが使えるページに付けるデコレーター。
    メニューを隠すだけでなく、URLを直接入力されてもここで拒否する。
    """
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            flash("ログインしてください。", "warning")
            return redirect(url_for("login"))
        if g.user["role"] != "manager":
            flash("このページは店長のみ利用できます。", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped_view


# =========================
# ログイン / ログアウト
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    # すでにログイン中ならトップへ
    if g.user:
        return redirect(url_for("index"))

    if request.method == "POST":

        employee_id = request.form.get("employee_id", "").strip().upper()
        password = request.form.get("password", "")

        conn = get_db_connection()
        employee = conn.execute(
            "SELECT * FROM employees WHERE employee_id = ?", (employee_id,)
        ).fetchone()
        conn.close()

        # IDとパスワードのどちらが違うかは教えない（不正ログイン対策）
        if employee is None or not check_password_hash(employee["password_hash"], password):
            flash("従業員IDまたはパスワードが違います。", "danger")
            return render_template("login.html", employee_id=employee_id)

        # ログイン成功：セッションに従業員IDを保存
        session.clear()
        session["employee_id"] = employee["employee_id"]

        flash(f"{employee['employee_name']}さん、お疲れさまです。", "success")
        return redirect(url_for("index"))

    return render_template("login.html", employee_id="")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("ログアウトしました。", "success")
    return redirect(url_for("login"))


# =========================
# トップページ
# =========================

@app.route("/")
@login_required
def index():

    # 商品名の検索キーワード（?q=ミルク など）
    keyword = request.args.get("q", "").strip()

    conn = get_db_connection()
    products = get_stock_list(conn, keyword)
    conn.close()

    # 不足している商品の数（発注リストへの案内に使う）
    shortage_count = len([p for p in products if p["difference"] < 0])

    return render_template(
        "index.html",
        products=products,
        keyword=keyword,
        shortage_count=shortage_count,
        greeting=get_greeting(),
        today=format_today()
    )


# 「あと何日で切れそうか」を計算するときに見る期間（日数）
FORECAST_DAYS = 14


def get_stock_list(conn, keyword=""):
    """
    在庫一覧を取得し、過不足と「あと何日で切れそうか」を計算して返す。

    あと◯日の計算方法：
      直近14日間の「消費＋廃棄」の合計 ÷ 14 ＝ 1日あたりの使用量
      現在庫 ÷ 1日あたりの使用量 ＝ あと何日もつか
    """
    since = (datetime.now(JST) - timedelta(days=FORECAST_DAYS)).strftime("%Y-%m-%d")

    sql = """
        SELECT
            products.product_id,
            products.product_name,
            products.unit,
            products.target_stock,
            products.current_stock,
            products.current_stock - products.target_stock AS difference,
            -- 直近14日間の消費＋廃棄の合計（履歴がなければ 0）
            COALESCE(SUM(inventory_logs.quantity), 0) AS used_quantity
        FROM products
        LEFT JOIN inventory_logs
            ON inventory_logs.product_id = products.product_id
            AND date(inventory_logs.created_at) >= ?
            AND inventory_logs.category_id IN (
                SELECT category_id FROM categories WHERE category_name IN ('消費', '廃棄')
            )
    """
    params = [since]

    if keyword:
        sql += " WHERE products.product_name LIKE ?"
        params.append(f"%{keyword}%")

    sql += " GROUP BY products.product_id ORDER BY products.product_id"

    rows = conn.execute(sql, params).fetchall()

    # テンプレートで使いやすいように辞書に変換し、計算結果を追加する
    products = []
    for row in rows:
        product = dict(row)

        daily_usage = product["used_quantity"] / FORECAST_DAYS

        if daily_usage > 0:
            product["days_left"] = int(product["current_stock"] / daily_usage)
        else:
            product["days_left"] = None   # 使用実績がないので計算できない

        # 残量バーの長さ（適正在庫に対する割合。最大100%）
        if product["target_stock"] > 0:
            product["stock_percent"] = min(100, int(product["current_stock"] * 100 / product["target_stock"]))
        else:
            product["stock_percent"] = 100

        products.append(product)

    return products


def get_greeting():
    """
    時間帯に合わせたあいさつを返す。
    """
    hour = datetime.now(JST).hour

    if hour < 11:
        return "おはようございます"
    elif hour < 17:
        return "こんにちは"
    else:
        return "お疲れさまです"


def format_today():
    """
    今日の日付を「2026年9月24日（木）」の形で返す。
    """
    now = datetime.now(JST)
    weekdays = ["月", "火", "水", "木", "金", "土", "日"]
    return f"{now.year}年{now.month}月{now.day}日（{weekdays[now.weekday()]}）"


# =========================
# 発注リスト
# =========================

@app.route("/orders")
@login_required
def orders():

    conn = get_db_connection()
    products = get_stock_list(conn)
    conn.close()

    # 適正在庫を下回っている商品 → 不足分を発注
    order_items = []
    # 足りてはいるが、あと3日以内に切れそうな商品 → 注意
    warning_items = []

    for product in products:
        if product["difference"] < 0:
            product["order_quantity"] = -product["difference"]
            order_items.append(product)
        elif product["days_left"] is not None and product["days_left"] <= 3:
            warning_items.append(product)

    return render_template(
        "orders.html",
        order_items=order_items,
        warning_items=warning_items,
        today=format_today()
    )


# =========================
# 入出荷入力ページ
# =========================

@app.route("/input", methods=["GET", "POST"])
@login_required
def inventory_input():

    # -------------------------
    # POST：フォームの登録処理
    # -------------------------
    if request.method == "POST":

        error = register_inventory(request.form)

        if error is None:
            flash_undo(f"{g.last_log_text}を登録しました。", g.last_log_id)
            return redirect(url_for("index"))

        # エラー時は入力画面を再表示（入力内容は残す）
        flash(error, "danger")

    # -------------------------
    # GET（またはエラー時）：入力画面の表示
    # -------------------------
    conn = get_db_connection()

    # 商品一覧
    products = conn.execute(
        """
        SELECT
            product_id,
            product_name,
            unit,
            current_stock
        FROM products
        ORDER BY product_id
        """
    ).fetchall()

    # 入荷・消費・廃棄
    categories = conn.execute(
        """
        SELECT
            category_id,
            category_name
        FROM categories
        ORDER BY category_id
        """
    ).fetchall()

    # 担当者
    employees = conn.execute(
        """
        SELECT
            employee_id,
            employee_name
        FROM employees
        ORDER BY employee_id
        """
    ).fetchall()

    conn.close()

    return render_template(
        "input.html",
        products=products,
        categories=categories,
        employees=employees,
        form=request.form
    )


@app.route("/input/quick", methods=["POST"])
@login_required
def inventory_quick():
    """
    ワンタップ登録：「ミルク −1」のボタンを押すだけで登録する。
    数量は1、担当者はログイン中の人で固定。
    登録処理そのものは通常の入力と同じ register_inventory() を使う。
    """
    form = {
        "product_id": request.form.get("product_id", ""),
        "category_id": request.form.get("category_id", ""),
        "quantity": "1",
        "employee_id": g.user["employee_id"],
        "memo": "ワンタップ登録",
    }

    error = register_inventory(form)

    if error is None:
        flash_undo(f"{g.last_log_text}を登録しました。", g.last_log_id)
    else:
        flash(error, "danger")

    return redirect(url_for("inventory_input"))


def flash_undo(message, log_id):
    """
    「取り消す」ボタン付きのお知らせを出す。
    flash() の第2引数（カテゴリ）に "undo:ログID" を入れておき、
    base.html 側でボタンを表示する。
    """
    flash(message, f"undo:{log_id}")


# 取り消しできるのは登録から何分以内か
UNDO_MINUTES = 10


@app.route("/logs/<int:log_id>/undo", methods=["POST"])
@login_required
def log_undo(log_id):
    """
    登録の取り消し：履歴を削除し、在庫を元に戻す。
    ・登録から10分以内のみ
    ・本人の登録のみ（店長は全員分を取り消せる）
    """
    conn = get_db_connection()

    log = conn.execute(
        """
        SELECT inventory_logs.*, categories.category_name, products.current_stock
        FROM inventory_logs
        JOIN categories ON inventory_logs.category_id = categories.category_id
        JOIN products ON inventory_logs.product_id = products.product_id
        WHERE inventory_logs.id = ?
        """,
        (log_id,)
    ).fetchone()

    error = None
    limit = (datetime.now(JST) - timedelta(minutes=UNDO_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")

    if log is None:
        error = "取り消す履歴が見つかりません。"
    elif log["employee_id"] != g.user["employee_id"] and g.user["role"] != "manager":
        error = "他の人の登録は取り消せません。"
    elif log["created_at"] < limit:
        error = f"登録から{UNDO_MINUTES}分以上たったため取り消せません。"
    else:
        # 登録したときと逆向きに在庫を戻す
        if log["category_name"] == "入荷":
            change = -log["quantity"]
        else:
            change = log["quantity"]

        if log["current_stock"] + change < 0:
            error = "すでに在庫を使っているため取り消せません。"

    if error:
        conn.close()
        flash(error, "danger")
        return redirect(request.referrer or url_for("index"))

    with conn:
        conn.execute("DELETE FROM inventory_logs WHERE id = ?", (log_id,))
        conn.execute(
            "UPDATE products SET current_stock = current_stock + ? WHERE product_id = ?",
            (change, log["product_id"])
        )

    conn.close()

    flash("登録を取り消しました。", "success")
    return redirect(request.referrer or url_for("index"))


# =========================
# 棚卸し
# 実際に数えた数を入力すると、帳簿（current_stock）との差を自動で調整する
# =========================

@app.route("/stocktake", methods=["GET", "POST"])
@login_required
def stocktake():

    conn = get_db_connection()

    products = conn.execute(
        "SELECT product_id, product_name, unit, current_stock FROM products ORDER BY product_id"
    ).fetchall()

    if request.method == "POST":

        # 入荷・廃棄の区分IDを取得（増えていたら入荷、減っていたら廃棄として記録）
        categories = {
            row["category_name"]: row["category_id"]
            for row in conn.execute("SELECT category_id, category_name FROM categories")
        }

        adjustments = []   # (商品, 差) のリスト

        for product in products:
            # 入力欄の name は count_P001 のような形
            value = request.form.get(f"count_{product['product_id']}", "").strip()

            # 空欄の商品は数えていないものとしてスキップ
            if value == "":
                continue

            counted = to_int(value)
            if counted is None:
                conn.close()
                flash(f"{product['product_name']}の数は0〜{MAX_NUMBER}の数字で入力してください。", "danger")
                return render_template("stocktake.html", products=products, form=request.form)

            diff = counted - product["current_stock"]
            if diff != 0:
                adjustments.append((product, diff))

        if not adjustments:
            conn.close()
            flash("帳簿と実際の数が一致しました。調整はありません。", "success")
            return redirect(url_for("index"))

        created_at = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")

        # すべての商品の調整を1つのトランザクションで行う
        with conn:
            for product, diff in adjustments:
                if diff > 0:
                    category_id = categories["入荷"]
                else:
                    category_id = categories["廃棄"]

                conn.execute(
                    """
                    INSERT INTO inventory_logs
                        (created_at, product_id, category_id, quantity, employee_id, memo)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (created_at, product["product_id"], category_id, abs(diff),
                     g.user["employee_id"], "棚卸し調整")
                )
                conn.execute(
                    "UPDATE products SET current_stock = current_stock + ? WHERE product_id = ?",
                    (diff, product["product_id"])
                )

        conn.close()

        flash(f"棚卸しを反映しました（{len(adjustments)}件を調整）。", "success")
        return redirect(url_for("index"))

    conn.close()

    return render_template("stocktake.html", products=products, form={})


def register_inventory(form):
    """
    入出荷を登録する処理。
    成功したら None、失敗したらエラーメッセージを返す。
    """

    product_id = form.get("product_id", "")
    category_id = form.get("category_id", "")
    employee_id = form.get("employee_id", "")
    memo = form.get("memo", "").strip()

    # 数量が数字かどうか確認
    try:
        quantity = int(form.get("quantity", ""))
    except ValueError:
        return "数量は数字で入力してください。"

    if quantity < 1 or quantity > MAX_NUMBER:
        return f"数量は1〜{MAX_NUMBER}の範囲で入力してください。"

    if not product_id or not category_id or not employee_id:
        return "未入力の項目があります。"

    if len(memo) > MAX_MEMO_LENGTH:
        return f"メモは{MAX_MEMO_LENGTH}文字以内で入力してください。"

    conn = get_db_connection()

    try:
        # 選択された商品・区分・担当者がDBに存在するか確認
        product = conn.execute(
            "SELECT product_name, unit, current_stock FROM products WHERE product_id = ?",
            (product_id,)
        ).fetchone()

        category = conn.execute(
            "SELECT category_name FROM categories WHERE category_id = ?",
            (category_id,)
        ).fetchone()

        employee = conn.execute(
            "SELECT employee_id FROM employees WHERE employee_id = ?",
            (employee_id,)
        ).fetchone()

        if product is None or category is None or employee is None:
            return "選択内容が正しくありません。もう一度選び直してください。"

        # 入荷なら +、消費・廃棄なら −
        if category["category_name"] == "入荷":
            change = quantity
        else:
            change = -quantity

        # 在庫がマイナスになる場合は登録しない
        if product["current_stock"] + change < 0:
            return (
                f"在庫が不足しています。"
                f"{product['product_name']}の現在庫は"
                f"{product['current_stock']}{product['unit']}です。"
            )

        created_at = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")

        # with conn: の中は1つのトランザクション
        # 途中でエラーが起きたら両方とも取り消し（ロールバック）される
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO inventory_logs (
                    created_at,
                    product_id,
                    category_id,
                    quantity,
                    employee_id,
                    memo
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (created_at, product_id, category_id, quantity, employee_id, memo)
            )

            conn.execute(
                """
                UPDATE products
                SET current_stock = current_stock + ?
                WHERE product_id = ?
                """,
                (change, product_id)
            )

        # 呼び出し元でお知らせ（トースト）と「取り消す」ボタンに使う
        # g はこのリクエストの間だけ使える入れ物
        sign = "+" if change > 0 else "−"
        g.last_log_id = cursor.lastrowid
        g.last_log_text = (
            f"{product['product_name']} {sign}{quantity}{product['unit']}"
            f"（{category['category_name']}）"
        )

        return None

    finally:
        conn.close()


# =========================
# 履歴一覧ページ
# =========================

@app.route("/logs")
@login_required
def logs():

    # URLの ?date_from=...&product_id=... から絞り込み条件を受け取る
    # 未指定なら空文字（＝絞り込みなし）
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    product_id = request.args.get("product_id", "")
    category_id = request.args.get("category_id", "")

    # 基本のSQL（JOINで商品名・区分名・担当者名もまとめて取得）
    sql = """
        SELECT
            inventory_logs.created_at,
            products.product_name,
            products.unit,
            categories.category_id,
            categories.category_name,
            inventory_logs.quantity,
            employees.employee_name,
            inventory_logs.memo
        FROM inventory_logs
        JOIN products ON inventory_logs.product_id = products.product_id
        JOIN categories ON inventory_logs.category_id = categories.category_id
        JOIN employees ON inventory_logs.employee_id = employees.employee_id
        WHERE 1 = 1
    """
    params = []

    # 条件が入力されているものだけ WHERE に追加する
    # （値は必ず ? で渡す：SQLインジェクション対策）
    if date_from:
        sql += " AND date(inventory_logs.created_at) >= ?"
        params.append(date_from)

    if date_to:
        sql += " AND date(inventory_logs.created_at) <= ?"
        params.append(date_to)

    if product_id:
        sql += " AND inventory_logs.product_id = ?"
        params.append(product_id)

    if category_id:
        sql += " AND inventory_logs.category_id = ?"
        params.append(category_id)

    # 新しい順に表示
    sql += " ORDER BY inventory_logs.created_at DESC, inventory_logs.id DESC"

    conn = get_db_connection()

    log_list = conn.execute(sql, params).fetchall()

    # 絞り込み用プルダウンの選択肢
    products = conn.execute(
        "SELECT product_id, product_name FROM products ORDER BY product_id"
    ).fetchall()

    categories = conn.execute(
        "SELECT category_id, category_name FROM categories ORDER BY category_id"
    ).fetchall()

    conn.close()

    return render_template(
        "logs.html",
        logs=log_list,
        products=products,
        categories=categories,
        filters=request.args
    )


# =========================
# マスタ管理ページ（商品・従業員）
# ※ 将来ログイン機能を作ったら「店長のみ」に制限する
# =========================

@app.route("/master")
@manager_required
def master():

    conn = get_db_connection()

    products = conn.execute(
        """
        SELECT product_id, product_name, unit, target_stock, current_stock
        FROM products
        ORDER BY product_id
        """
    ).fetchall()

    employees = conn.execute(
        "SELECT employee_id, employee_name, role FROM employees ORDER BY employee_id"
    ).fetchall()

    conn.close()

    return render_template(
        "master.html",
        products=products,
        employees=employees
    )


def to_int(value):
    """
    文字列を 0〜MAX_NUMBER の整数に変換する。変換できなければ None を返す。
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None

    if number < 0 or number > MAX_NUMBER:
        return None

    return number


# ---------- 商品 ----------

@app.route("/master/products/add", methods=["POST"])
@manager_required
def product_add():

    product_id = request.form.get("product_id", "").strip().upper()
    product_name = request.form.get("product_name", "").strip()
    unit = request.form.get("unit", "").strip()
    target_stock = to_int(request.form.get("target_stock"))
    current_stock = to_int(request.form.get("current_stock"))

    if not product_id or not product_name or not unit:
        flash("商品ID・商品名・単位を入力してください。", "danger")
        return redirect(url_for("master"))

    if not is_valid_id(product_id):
        flash("商品IDは英数字10文字以内で入力してください（例：P005）。", "danger")
        return redirect(url_for("master"))

    if len(product_name) > MAX_NAME_LENGTH or len(unit) > MAX_UNIT_LENGTH:
        flash(f"商品名は{MAX_NAME_LENGTH}文字、単位は{MAX_UNIT_LENGTH}文字以内で入力してください。", "danger")
        return redirect(url_for("master"))

    if target_stock is None or current_stock is None:
        flash(f"適正在庫・現在庫は0〜{MAX_NUMBER}の数字で入力してください。", "danger")
        return redirect(url_for("master"))

    conn = get_db_connection()

    # 同じ商品IDがすでにあるか確認
    exists = conn.execute(
        "SELECT 1 FROM products WHERE product_id = ?", (product_id,)
    ).fetchone()

    if exists:
        conn.close()
        flash(f"商品ID「{product_id}」はすでに使われています。", "danger")
        return redirect(url_for("master"))

    with conn:
        conn.execute(
            """
            INSERT INTO products (product_id, product_name, unit, target_stock, current_stock)
            VALUES (?, ?, ?, ?, ?)
            """,
            (product_id, product_name, unit, target_stock, current_stock)
        )

    conn.close()

    flash(f"商品「{product_name}」を登録しました。", "success")
    return redirect(url_for("master"))


@app.route("/master/products/<product_id>/edit", methods=["GET", "POST"])
@manager_required
def product_edit(product_id):

    conn = get_db_connection()

    product = conn.execute(
        "SELECT * FROM products WHERE product_id = ?", (product_id,)
    ).fetchone()

    if product is None:
        conn.close()
        flash("商品が見つかりません。", "danger")
        return redirect(url_for("master"))

    if request.method == "POST":

        product_name = request.form.get("product_name", "").strip()
        unit = request.form.get("unit", "").strip()
        target_stock = to_int(request.form.get("target_stock"))

        if (not product_name or not unit or target_stock is None
                or len(product_name) > MAX_NAME_LENGTH or len(unit) > MAX_UNIT_LENGTH):
            conn.close()
            flash(f"商品名（{MAX_NAME_LENGTH}文字以内）・単位（{MAX_UNIT_LENGTH}文字以内）・適正在庫（0〜{MAX_NUMBER}）を正しく入力してください。", "danger")
            return redirect(url_for("product_edit", product_id=product_id))

        # 現在庫はここでは変更しない（入出荷入力で増減させ、履歴を残すため）
        with conn:
            conn.execute(
                """
                UPDATE products
                SET product_name = ?, unit = ?, target_stock = ?
                WHERE product_id = ?
                """,
                (product_name, unit, target_stock, product_id)
            )

        conn.close()

        flash(f"商品「{product_name}」を更新しました。", "success")
        return redirect(url_for("master"))

    conn.close()

    return render_template("product_edit.html", product=product)


@app.route("/master/products/<product_id>/delete", methods=["POST"])
@manager_required
def product_delete(product_id):

    conn = get_db_connection()

    # 履歴がある商品は削除しない（履歴の商品名が分からなくなるため）
    used = conn.execute(
        "SELECT 1 FROM inventory_logs WHERE product_id = ? LIMIT 1", (product_id,)
    ).fetchone()

    if used:
        conn.close()
        flash("この商品には入出荷の履歴があるため削除できません。", "danger")
        return redirect(url_for("master"))

    with conn:
        conn.execute("DELETE FROM products WHERE product_id = ?", (product_id,))

    conn.close()

    flash("商品を削除しました。", "success")
    return redirect(url_for("master"))


# ---------- 従業員 ----------

@app.route("/master/employees/add", methods=["POST"])
@manager_required
def employee_add():

    employee_id = request.form.get("employee_id", "").strip().upper()
    employee_name = request.form.get("employee_name", "").strip()
    role = request.form.get("role", "staff")
    password = request.form.get("password", "")

    if not employee_id or not employee_name:
        flash("従業員ID・名前を入力してください。", "danger")
        return redirect(url_for("master"))

    if not is_valid_id(employee_id):
        flash("従業員IDは英数字10文字以内で入力してください（例：E004）。", "danger")
        return redirect(url_for("master"))

    if len(employee_name) > MAX_NAME_LENGTH:
        flash(f"名前は{MAX_NAME_LENGTH}文字以内で入力してください。", "danger")
        return redirect(url_for("master"))

    if role not in ("manager", "staff"):
        flash("権限の指定が正しくありません。", "danger")
        return redirect(url_for("master"))

    if len(password) < 4:
        flash("パスワードは4文字以上で入力してください。", "danger")
        return redirect(url_for("master"))

    conn = get_db_connection()

    exists = conn.execute(
        "SELECT 1 FROM employees WHERE employee_id = ?", (employee_id,)
    ).fetchone()

    if exists:
        conn.close()
        flash(f"従業員ID「{employee_id}」はすでに使われています。", "danger")
        return redirect(url_for("master"))

    with conn:
        conn.execute(
            """
            INSERT INTO employees (employee_id, employee_name, role, password_hash)
            VALUES (?, ?, ?, ?)
            """,
            (employee_id, employee_name, role, generate_password_hash(password))
        )

    conn.close()

    flash(f"従業員「{employee_name}」を登録しました。", "success")
    return redirect(url_for("master"))


@app.route("/master/employees/<employee_id>/edit", methods=["GET", "POST"])
@manager_required
def employee_edit(employee_id):

    conn = get_db_connection()

    employee = conn.execute(
        "SELECT * FROM employees WHERE employee_id = ?", (employee_id,)
    ).fetchone()

    if employee is None:
        conn.close()
        flash("従業員が見つかりません。", "danger")
        return redirect(url_for("master"))

    if request.method == "POST":

        employee_name = request.form.get("employee_name", "").strip()
        role = request.form.get("role", "staff")
        password = request.form.get("password", "")

        if not employee_name or len(employee_name) > MAX_NAME_LENGTH:
            conn.close()
            flash(f"名前を{MAX_NAME_LENGTH}文字以内で入力してください。", "danger")
            return redirect(url_for("employee_edit", employee_id=employee_id))

        if role not in ("manager", "staff"):
            conn.close()
            flash("権限の指定が正しくありません。", "danger")
            return redirect(url_for("employee_edit", employee_id=employee_id))

        # 自分自身を店長から外すと、誰もマスタ管理できなくなる恐れがあるため禁止
        if employee_id == g.user["employee_id"] and role != "manager":
            conn.close()
            flash("自分自身の権限は変更できません。", "danger")
            return redirect(url_for("employee_edit", employee_id=employee_id))

        # パスワード欄は空なら変更しない
        if password and len(password) < 4:
            conn.close()
            flash("パスワードは4文字以上で入力してください。", "danger")
            return redirect(url_for("employee_edit", employee_id=employee_id))

        with conn:
            conn.execute(
                "UPDATE employees SET employee_name = ?, role = ? WHERE employee_id = ?",
                (employee_name, role, employee_id)
            )

            if password:
                conn.execute(
                    "UPDATE employees SET password_hash = ? WHERE employee_id = ?",
                    (generate_password_hash(password), employee_id)
                )

        conn.close()

        flash(f"従業員「{employee_name}」を更新しました。", "success")
        return redirect(url_for("master"))

    conn.close()

    return render_template("employee_edit.html", employee=employee)


@app.route("/master/employees/<employee_id>/delete", methods=["POST"])
@manager_required
def employee_delete(employee_id):

    # ログイン中の自分自身は削除できない
    if employee_id == g.user["employee_id"]:
        flash("自分自身は削除できません。", "danger")
        return redirect(url_for("master"))

    conn = get_db_connection()

    # 履歴に登場する従業員は削除しない
    used = conn.execute(
        "SELECT 1 FROM inventory_logs WHERE employee_id = ? LIMIT 1", (employee_id,)
    ).fetchone()

    if used:
        conn.close()
        flash("この従業員には入出荷の履歴があるため削除できません。", "danger")
        return redirect(url_for("master"))

    with conn:
        conn.execute("DELETE FROM employees WHERE employee_id = ?", (employee_id,))

    conn.close()

    flash("従業員を削除しました。", "success")
    return redirect(url_for("master"))


# =========================
# Flask起動
# =========================

if __name__ == "__main__":
    app.run(debug=True)