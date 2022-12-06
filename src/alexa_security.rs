use hyper::Uri;
use http::uri::Scheme;
use thiserror::Error;
use reqwest::{
    Client,
    ClientBuilder,
};
use openssl::{
    x509::{X509, X509StoreContext, store::X509StoreBuilder}, 
    stack::Stack,
    sign::Verifier as HashVerifier,
    hash::MessageDigest,
};

use std::collections::VecDeque;

#[derive(Error, Debug)]
#[error("error in creating reqwest client: {0:?}")]
pub struct BuildError(#[source] reqwest::Error);

#[derive(Error, Debug)]
pub enum Error{
    #[error("no scheme in SignatureCertChainURL")]
    NoSchemeError,

    #[error("invalid scheme: {0:?}")]
    InvalidSchemeError(Scheme),

    #[error("error fetching cert chain from provided location: {0:?}")]
    NetworkError(#[source] reqwest::Error),

    #[error("error with response when fetching certificate chain: {0:?}")]
    CertResponseError(#[source] reqwest::Error),

    #[error("error parsing certificate as X509: {0:?}")]
    CertParseError(#[source] openssl::error::ErrorStack),

    #[error("unexpected error with openssl system: {0:?}")]
    OpensslError(#[source] openssl::error::ErrorStack),

    #[error("no certs provided by cert chain url")]
    NoCertsError,

    #[error("provided cert could not be verified against chain")]
    FailureToVerifyError,

    #[error("error decoding signature as base64: {0:?}")]
    Base64DecodeError(#[source] base64::DecodeError),

    #[error("message signature does not match derived signature")]
    SignatureInequalityError, 
}

pub struct VerifierBuilder {
    client: Option<ClientBuilder>
}

impl VerifierBuilder {
    pub fn new() -> Self {
        Self{
            client: None,
        }
    }

    pub fn with_client(mut self, client: ClientBuilder) -> VerifierBuilder {
        self.client = Some(client);
        self
    }

    pub fn build(self) -> Result<Verifier, BuildError> {
        let client = match self.client {
            Some(client) => client.build(),
            None => ClientBuilder::new().build(),
        }.map_err(|err| BuildError(err))?;

        Ok(Verifier{
            client: client,
        })
    }
}

pub struct Verifier {
   client: Client,
}

impl Verifier {
    pub fn new() -> Result<Verifier, BuildError> {
        VerifierBuilder::new().build()
    }

    pub async fn validate_signature_cert_chain_url(&self, uri: Uri, signature: &[u8], body: &[u8]) -> Result<(), Error> {
        let scheme = match uri.scheme() {
            Some(scheme) => scheme,
            None => return Err(Error::NoSchemeError),
        };

        if *scheme != Scheme::HTTPS {
            return Err(Error::InvalidSchemeError(scheme.clone()));
        };

        let rsp = self.client
            .get(uri.to_string())
            .send()
            .await
            .map_err(|err| Error::NetworkError(err))?;

        rsp.error_for_status_ref()
            .map_err(|err| Error::CertResponseError(err))?;

        let mut certs = rsp
            .text()
            .await
            .map_err(|err| Error::CertResponseError(err))?
            .split("-----END CERTIFICATE-----")
            .filter(|x| !x.is_empty())
            .map(|x| format!("{}-----END CERTIFICATE-----", x))
            .map(|x| X509::from_pem(x.as_bytes()))
            .collect::<Result<VecDeque<X509>, openssl::error::ErrorStack>>()
            .map_err(|err| Error::CertParseError(err))?;

        let my_cert = certs.pop_front().ok_or(Error::NoCertsError)?;

        let store = {
            let mut store_builder = X509StoreBuilder::new()
                .map_err(|err| Error::OpensslError(err))?;

            store_builder.set_default_paths()
                .map_err(|err| Error::OpensslError(err))?;

            store_builder.build()
        };

        let chain = {
            let mut chain: Stack<X509> = Stack::new()
                .map_err(|err| Error::OpensslError(err))?;

            for c in certs.into_iter().rev() {
                chain.push(c)
                    .map_err(|err| Error::OpensslError(err))?;
            };

            chain
        };

        let verified = {
            let mut store_ctx = X509StoreContext::new()
                .map_err(|err| Error::OpensslError(err))?;
            let mut result = Ok(false);
            store_ctx.init(
                &store,
                &my_cert,
                &chain,
                |ctx| {
                    result = ctx.verify_cert();
                    Ok(())
                },
            ).map_err(|err| Error::OpensslError(err))?;

            result
                .map_err(|err| Error::OpensslError(err))?
        };

        if !verified {
            return Err(Error::FailureToVerifyError);
        };

        let decoded_sig = base64::decode(signature)
            .map_err(|err| Error::Base64DecodeError(err))?;

        let public_key = my_cert.public_key()
            .map_err(|err| Error::OpensslError(err))?;

        let sig_verified = {
            let mut verifier = HashVerifier::new(MessageDigest::sha256(), &public_key)
                .map_err(|err| Error::OpensslError(err))?;

            verifier.verify_oneshot(decoded_sig.as_slice(), body)
                .map_err(|err| Error::OpensslError(err))?
        };

        if !sig_verified {
            return Err(Error::SignatureInequalityError);
        };

        Ok(())
    }
}
