use abs_admin::controller::{
    img_controller, sys_auth_controller, sys_dict_controller, sys_permission_controller,
    sys_role_controller, sys_user_controller,
};
use abs_admin::domain::table;
use abs_admin::service::CONTEXT;

use axum::extract::Request;
use axum::routing::{get, post};

use axum::{
    body::Body,
    http::{self, Response, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    Router,
};

async fn global_options_middleware(req: Request, next: Next) -> impl IntoResponse {
    log::info!("cors");
    if req.method() == http::Method::OPTIONS {
        // 返回统一的OPTIONS响应
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            .header(
                "Access-Control-Allow-Headers",
                "X-PINGOTHER, Content-Type, Authorization",
            )
            .body(Body::empty())
            .unwrap()
    } else {
        // 对于非OPTIONS请求，继续传递到下一个中间件或路由处理器
        next.run(req).await
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    //log
    abs_admin::config::log::init_log();
    //database
    CONTEXT.init_database().await;
    table::sync_tables(&CONTEXT.rb).await;
    table::sync_tables_data(&CONTEXT.rb).await;
    //router
    let app = Router::new()
        .route("/", get(|| async { "[abs_admin] Hello !" }))
        .route("/admin/sys_login", post(sys_user_controller::login))
        .route("/admin/sys_user_info", post(sys_user_controller::info))
        .route("/admin/sys_user_detail", post(sys_user_controller::detail))
        .route(
            "/admin/sys_permission_update",
            post(sys_permission_controller::update),
        )
        .route(
            "/admin/sys_permission_remove",
            post(sys_permission_controller::remove),
        )
        .route(
            "/admin/sys_permission_add",
            post(sys_permission_controller::add),
        )
        .route(
            "/admin/sys_permission_page",
            post(sys_permission_controller::page),
        )
        .route(
            "/admin/sys_permission_all",
            post(sys_permission_controller::all),
        )
        .route(
            "/admin/sys_permission_layer_top",
            post(sys_permission_controller::layer_top),
        )
        .route("/admin/sys_user_add", post(sys_user_controller::add))
        .route("/admin/sys_user_page", post(sys_user_controller::page))
        .route("/admin/sys_user_remove", post(sys_user_controller::remove))
        .route("/admin/sys_user_update", post(sys_user_controller::update))
        .route("/admin/sys_role_add", post(sys_role_controller::add))
        .route("/admin/sys_role_update", post(sys_role_controller::update))
        .route("/admin/sys_role_delete", post(sys_role_controller::remove))
        .route("/admin/sys_role_page", post(sys_role_controller::page))
        .route(
            "/admin/sys_role_layer_top",
            post(sys_role_controller::layer_top),
        )
        .route("/admin/sys_dict_add", post(sys_dict_controller::add))
        .route("/admin/sys_dict_update", post(sys_dict_controller::update))
        .route("/admin/sys_dict_remove", post(sys_dict_controller::remove))
        .route("/admin/sys_dict_page", post(sys_dict_controller::page))
        .route("/admin/auth/check", post(sys_auth_controller::check))
        .route("/admin/captcha", get(img_controller::captcha))
        // 应用中间件到所有请求
        .layer(axum::middleware::from_fn(
            abs_admin::middleware::auth_axum::auth,
        ))
        .layer(middleware::from_fn(global_options_middleware));
    let listener = tokio::net::TcpListener::bind(&CONTEXT.config.server_url)
        .await
        .unwrap();
    axum::serve(listener, app).await
}
