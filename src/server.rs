use crate::handlers::AlexaHandler;
use axum::{
    self,
    response::{self, IntoResponse, Response},
    routing, Router,
    http::{
        header::HeaderMap,
        StatusCode,
    },
    body::Bytes,
};
use futures::{Future, FutureExt};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use log::{info, error, debug};
use std::fmt::Debug;
use hyper::Uri;
use crate::alexa_security::Verifier;

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
struct AlexaResponse {
   version: String,
   response: AlexaResponseObject,
}

#[derive(Debug, Serialize)]
struct AlexaResponseObject {
    #[serde(rename = "outputSpeech")]
    output_speech: AlexaOutputSpeech,

    #[serde(rename = "shouldEndSession")]
    should_end_session: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum AlexaOutputSpeech {
    PlainText { text: String },
    SSML { ssml: String },
}

pub struct Server {
    port: u16,
    application_id: String,
    handler: AlexaHandler,
    verifier: Verifier,
}

struct ResponseError {
    msg: String,
    status: StatusCode,
}

impl ResponseError {
    fn new(status: StatusCode, msg: String) -> Self {
        Self{
            msg: msg,
            status: status,
        }
    }

    fn to_response(self) -> Response {
        if self.status.is_client_error() {
            debug!("{}", self.msg);
        } else {
            error!("{}", self.msg);
        };

        (self.status, response::Json(ErrorResponse {
            error: self.msg,
        })).into_response()
    }
}

fn ok_rsp<T: Debug + Serialize>(rsp: T) -> Response {
    debug!("{:?}", rsp);

    (
        StatusCode::OK,
        response::Json(rsp)
    ).into_response()
}

impl Server {
    pub fn new(port: u16, handler: AlexaHandler, verifier: Verifier, application_id: String) -> Self {
        Self {
            port: port,
            application_id: application_id,
            handler: handler,
            verifier: verifier,
        }
    }

    pub fn serve(self) -> impl Future<Output = ()> {
        let port = self.port;
        let self_ptr = Arc::new(self);

        let latest_route = alexa_routes(self_ptr.clone());

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

        axum::Server::bind(&addr)
            .serve(latest_route.into_make_service())
            .then(|_| async { () })
    }

    async fn latest(&self) -> Result<Response, ResponseError> {
        info!("handling latest intent");
        let poop_time = self.handler
            .latest()
            .await
            .map_err(|error| ResponseError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{:?}", error)))?;

        Ok(ok_rsp(AlexaResponse{
            version: "1.0".to_string(),
            response: AlexaResponseObject{
                output_speech: match poop_time {
                    Some(time) => AlexaOutputSpeech::SSML{
                        ssml: format!("<speak>Riley last pooped on <say-as intepret-as=\"date\">{}</say-as> at {}.</speak>", time.format("%Y%m%d"), time.format("%I:%M %p")),
                    },
                    None => AlexaOutputSpeech::PlainText {
                        text: "Riley has not poooped in the last week".to_string(),
                    },
                },
                should_end_session: None,
            },
        }))
    }
}

fn alexa_routes(server: Arc<Server>) -> Router {
    Router::new().route(
        "/",
        routing::get(
            |body: Bytes, headers: HeaderMap| async move {
                info!("incoming request found");
                let rsp = (|| async move {
                    let signature_cert_chain_url = headers
                        .get("SignatureCertChainUrl")
                        .ok_or(ResponseError::new(StatusCode::FORBIDDEN, format!("no SignatureCertChainUrl header")))?
                        .to_str()
                        .map_err(|error| ResponseError::new(StatusCode::FORBIDDEN, format!("error parsing SignatureCertChainUrl: {:?}", error)))?
                        .parse::<Uri>()
                        .map_err(|error| ResponseError::new(StatusCode::FORBIDDEN, format!("error parsing SignatureCertChainUrl: {:?}", error)))?;

                    let signature = headers
                        .get("Signature-256")
                        .ok_or(ResponseError::new(StatusCode::FORBIDDEN, format!("no Signature-256 header")))?
                        .as_bytes();

                    server.verifier.validate_signature_cert_chain_url(signature_cert_chain_url, signature, &body)
                        .await
                        .map_err(|error| ResponseError::new(StatusCode::FORBIDDEN, format!("error validating SignatureCertChainUrl: {:?}", error)))?;

                    let input = serde_json::from_slice::<AlexaInput>(&body)
                        .map_err(|err| ResponseError::new(StatusCode::BAD_REQUEST, format!("could not parse request body as json: {:?}", err)))?;

                    if input.context.system.application.application_id != server.application_id {
                        return Err(ResponseError::new(StatusCode::BAD_REQUEST, format!("bad application id")));
                    };

                    let intent = match input.request {
                        AlexaRequest::IntentRequest(ref req) => req,
                        _ => {
                            return Err(ResponseError::new(StatusCode::BAD_REQUEST, format!("expected intent request")));
                        },
                    };

                    match intent.intent.name.as_str() {
                        "Latest" => server.latest().await,
                        _ => Err(ResponseError::new(StatusCode::BAD_REQUEST, format!("unknown intent found"))),
                    }
                })().await;

                match rsp {
                    Ok(r) => r,
                    Err(e) => e.to_response(),
                }
            },
        ),
    )
}

#[derive(Deserialize)]
struct AlexaInput {
    context: AlexaContext,
    request: AlexaRequest,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AlexaRequest {
    LaunchRequest,
    IntentRequest(IntentRequest),
    SessionEndedRequest,
    CanFulfillIntentRequest,
}

#[derive(Deserialize)]
struct IntentRequest {
    intent: AlexaIntent,
}

#[derive(Deserialize)]
struct AlexaIntent {
    name: String,
}

#[derive(Deserialize)]
struct AlexaContext {
    #[serde(rename = "System")]
    system: AlexaSystem,
}

#[derive(Deserialize)]
struct AlexaSystem {
    application: AlexaApplication,
}

#[derive(Deserialize)]
struct AlexaApplication {
    #[serde(rename = "applicationId")]
    application_id: String,
}

#[cfg(test)]
mod t {
    use super::*;

    use hyper::{
        Request,
        Body,
        StatusCode,
    };
    use tower::ServiceExt;
    use faux::when;
    use chrono::{
        Local,
        TimeZone,
    };

    mod test_latest {
        use super::*;
        macro_rules! test_latest {
            ($name:ident, $date:expr, $expected:expr) => {

                #[tokio::test]
                async fn $name() {
                    let mut handler = AlexaHandler::faux();
                    when!(handler.latest()).then(|_| {
                        Ok($date)
                    });
                    
                    let application_id = "12345";

                    let server = Arc::new(Server::new(8080, handler, application_id.to_string()));

                    let app = alexa_routes(server);

                    let body = format!(r#"{{"context": {{"System": {{ "application": {{"applicationId": "{}" }} }} }}, "request": {{"type": "IntentRequest", "intent": {{"name": "Latest"}} }} }}"#, application_id);

                    let test_request = Request::builder()
                        .uri("/")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap();

                    let resp = app
                        .oneshot(test_request)
                        .await
                        .unwrap();

                    let status = resp.status();
                    let body_bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
                    let body_str = String::from_utf8(body_bytes.into_iter().collect()).unwrap();

                    assert_eq!(status, StatusCode::OK, "bad status code: {}", body_str);
                    assert_eq!(body_str, $expected);
                }
            }
        }

        test_latest!(validtime, Some(Local.timestamp_opt(1234556789, 0).unwrap()), r#"{"version":"1.0","response":{"outputSpeech":{"type":"SSML","ssml":"<speak>Riley last pooped on <say-as intepret-as=\"date\">20090213</say-as> at 03:26 PM.</speak>"},"shouldEndSession":null}}"#);
        test_latest!(invalidtime, None, r#"{"version":"1.0","response":{"outputSpeech":{"type":"PlainText","text":"Riley has not poooped in the last week"},"shouldEndSession":null}}"#);
    }
}
