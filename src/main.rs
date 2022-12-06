mod config;
mod handlers;
mod server;
mod tadpoles;
mod alexa_security;
use std::error::Error;
use log::{info};
use env_logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args = config::read()?;

    let client = tadpoles::Client::new(args.user_name, args.password)?;

    let handler = handlers::AlexaHandler::new(client);
    let verifier = alexa_security::Verifier::new()?;

    info!("starting to serve");
    server::Server::new(args.port, handler, verifier, args.application_id)
        .serve()
        .await;
    info!("shutting down");

    Ok(())
}
