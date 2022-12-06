use std::{
    env::{self, VarError},
    num::ParseIntError,
};
use thiserror::Error;

pub struct Args {
    pub user_name: String,
    pub password: String,
    pub application_id: String,
    pub port: u16,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("error reading environment variable {env:?}: {err:?}")]
    ReadError { env: &'static str, err: VarError },

    #[error("error parsing environment variable {env:?}: {err:?}")]
    ParseError {
        env: &'static str,
        err: ParseIntError,
    },
}

static USER_NAME: &'static str = "POOPER_USER_NAME";
static PASSWORD: &'static str = "POOPER_PASSWORD";
static APPLICATION_ID: &'static str = "POOPER_PASSWORD";
static PORT: &'static str = "POOPER_PORT";

pub fn read() -> Result<Args, Error> {
    Ok(Args {
        user_name: env::var(USER_NAME).map_err(|err| Error::ReadError {
            env: USER_NAME,
            err: err,
        })?,
        password: env::var(PASSWORD).map_err(|err| Error::ReadError {
            env: PASSWORD,
            err: err,
        })?,
        application_id: env::var(APPLICATION_ID).map_err(|err| Error::ReadError {
            env: APPLICATION_ID,
            err: err,
        })?,
        port: env::var(PORT)
            .map_err(|err| Error::ReadError {
                env: PORT,
                err: err,
            })?
            .parse::<u16>()
            .map_err(|err| Error::ParseError {
                env: PORT,
                err: err,
            })?,
    })
}
