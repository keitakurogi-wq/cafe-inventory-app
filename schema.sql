PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS inventory_logs;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS categories;
DROP TABLE IF EXISTS employees;

CREATE TABLE products (
    product_id TEXT PRIMARY KEY,
    product_name TEXT NOT NULL,
    unit TEXT NOT NULL,
    target_stock INTEGER NOT NULL DEFAULT 0,
    current_stock INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE categories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_name TEXT NOT NULL
);

CREATE TABLE employees (
    employee_id TEXT PRIMARY KEY,
    employee_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'staff',  -- manager（店長） / staff（スタッフ）
    password_hash TEXT                   -- NULLならアプリ起動時に初期パスワードを設定
);

CREATE TABLE inventory_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    product_id TEXT NOT NULL,
    category_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    employee_id TEXT NOT NULL,
    memo TEXT,
    FOREIGN KEY (product_id) REFERENCES products(product_id),
    FOREIGN KEY (category_id) REFERENCES categories(category_id),
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

INSERT INTO products (
    product_id,
    product_name,
    unit,
    target_stock,
    current_stock
)
VALUES
    ('P001', 'コーヒー豆', 'kg', 10, 8),
    ('P002', 'ミルク', '本', 20, 15),
    ('P003', '砂糖', '袋', 5, 4),
    ('P004', '紙コップ', '個', 100, 80);

INSERT INTO categories (
    category_name
)
VALUES
    ('入荷'),
    ('消費'),
    ('廃棄');

INSERT INTO employees (
    employee_id,
    employee_name,
    role
)
VALUES
    ('E001', '山田店長', 'manager'),
    ('E002', '伊藤', 'staff'),
    ('E003', '佐藤', 'staff');