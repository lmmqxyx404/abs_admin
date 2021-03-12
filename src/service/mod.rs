use rbatis::rbatis::Rbatis;

use redis_service::*;
use sys_res_service::*;
use sys_role_res_service::*;
use sys_role_service::*;
use sys_user_role_service::*;
use sys_user_service::*;

use crate::config::app_config::ApplicationConfig;
use rbatis::core::runtime::runtime::{Builder,Runtime};

mod redis_service;
mod sys_config_service;
mod sys_res_service;
mod sys_role_res_service;
mod sys_role_service;
mod sys_sms_service;
mod sys_user_role_service;
mod sys_user_service;

pub struct ServiceContext {
    pub runtime: Runtime,
    pub config: ApplicationConfig,
    pub rbatis: Rbatis,
    pub redis_service: RedisService,
    pub sys_res_service: SysResService,
    pub sys_user_service: SysUserService,
    pub sys_role_service: SysRoleService,
    pub sys_role_res_service: SysRoleResService,
    pub sys_user_role_service: SysUserRoleService,
}

impl Default for ServiceContext {
    fn default() -> Self {
        let config = ApplicationConfig::default();
        let tokio_runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        ServiceContext {
            rbatis: tokio_runtime.block_on(async { crate::dao::init_rbatis(&config)}),
            redis_service: RedisService::new(&config.redis_url),
            sys_res_service: SysResService {},
            sys_user_service: SysUserService {},
            sys_role_service: SysRoleService {},
            sys_role_res_service: SysRoleResService {},
            sys_user_role_service: SysUserRoleService {},
            runtime: tokio_runtime,
            config,
        }
    }
}

lazy_static! {
    pub static ref CONTEXT: ServiceContext = ServiceContext::default();
}
