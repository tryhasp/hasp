use std::path::Path;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{AssertSqlSafe, ConnectOptions, Row};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub fn run_sql(db: &Path, script: &str) {
    runtime().block_on(async {
        let mut connection = SqliteConnectOptions::new()
            .filename(db)
            .create_if_missing(true)
            .connect()
            .await
            .unwrap();
        sqlx::raw_sql(AssertSqlSafe(script.to_owned()))
            .execute(&mut connection)
            .await
            .unwrap();
    });
}

pub fn query_strings(db: &Path, sql: &str) -> Vec<String> {
    runtime().block_on(async {
        let mut connection = SqliteConnectOptions::new()
            .filename(db)
            .read_only(true)
            .connect()
            .await
            .unwrap();
        sqlx::query(AssertSqlSafe(sql.to_owned()))
            .fetch_all(&mut connection)
            .await
            .unwrap()
            .iter()
            .map(|row| row.get::<String, _>(0))
            .collect()
    })
}
