use std::{convert::Infallible, time::Duration};

use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{body::Bytes, header as HyperHeaders, Method, StatusCode};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};

use super::tokio_thread::TransportThread;

use crate::{sentry_debug, ClientOptions, Envelope, Transport};

#[cfg(feature = "hyper-native-tls")]
type HyperClient = hyper_util::client::legacy::Client<
    hyper_tls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    UnsyncBoxBody<Bytes, Infallible>,
>;

#[cfg(feature = "hyper-rustls")]
type HyperClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    UnsyncBoxBody<Bytes, Infallible>,
>;

/// A [`Transport`] that sends events via the [`hyper`] library.
///
/// When the `transport` feature is enabled this will currently
/// be the default transport.  This is separately enabled by the
/// `reqwest` feature flag.
#[cfg_attr(doc_cfg, doc(cfg(feature = "hyper")))]
pub struct HyperHttpTransport {
    thread: TransportThread,
}

impl HyperHttpTransport {
    /// Creates a new Transport.
    pub fn new(options: &ClientOptions) -> Self {
        Self::new_internal(options, None)
    }

    /// Creates a new Transport that uses the specified [`HyperClient`].
    pub fn with_client(options: &ClientOptions, client: HyperClient) -> Self {
        Self::new_internal(options, Some(client))
    }

    fn new_internal(options: &ClientOptions, client: Option<HyperClient>) -> Self {
        let client = client.unwrap_or_else(|| {
            let builder = hyper_util::client::legacy::Client::builder(TokioExecutor::new());

            if options.http_proxy.is_some() {
                sentry_debug!("HTTP proxies are not supported with the hyper backend");
            };
            #[cfg(feature = "hyper-native-tls")]
            {
                let tls_connector: tokio_native_tls::TlsConnector =
                    native_tls::TlsConnector::builder()
                        .danger_accept_invalid_certs(options.accept_invalid_certs)
                        .build()
                        .unwrap()
                        .into();

                let https_connector = (HttpConnector::new(), tls_connector).into();
                builder.build(https_connector)
            }
            #[cfg(feature = "hyper-rustls")]
            {
                let https_connector = if options.accept_invalid_certs {
                    #[derive(Debug)]
                    struct NoCertVerifier;

                    use rustls::client::danger::{
                        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
                    };

                    impl ServerCertVerifier for NoCertVerifier {
                        fn verify_server_cert(
                            &self,
                            _end_entity: &rustls::pki_types::CertificateDer<'_>,
                            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                            _server_name: &rustls::pki_types::ServerName<'_>,
                            _ocsp_response: &[u8],
                            _now: rustls::pki_types::UnixTime,
                        ) -> Result<ServerCertVerified, rustls::Error> {
                            Ok(ServerCertVerified::assertion())
                        }

                        fn verify_tls12_signature(
                            &self,
                            _message: &[u8],
                            _cert: &rustls::pki_types::CertificateDer<'_>,
                            _dss: &rustls::DigitallySignedStruct,
                        ) -> Result<HandshakeSignatureValid, rustls::Error>
                        {
                            Ok(HandshakeSignatureValid::assertion())
                        }

                        fn verify_tls13_signature(
                            &self,
                            _message: &[u8],
                            _cert: &rustls::pki_types::CertificateDer<'_>,
                            _dss: &rustls::DigitallySignedStruct,
                        ) -> Result<HandshakeSignatureValid, rustls::Error>
                        {
                            Ok(HandshakeSignatureValid::assertion())
                        }

                        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                            // TODO: add all
                            vec![rustls::SignatureScheme::RSA_PKCS1_SHA256]
                        }
                    }

                    hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(
                        rustls::ClientConfig::builder()
                            .dangerous()
                            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerifier))
                            .with_no_client_auth(),
                    )
                } else {
                    hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots()
                }
                .https_only()
                .enable_http1()
                .enable_http2()
                .build();

                builder.build(https_connector)
            }
        });
        let dsn = options.dsn.as_ref().unwrap();
        let user_agent = options.user_agent.clone();
        let auth = dsn.to_auth(Some(&user_agent)).to_string();
        let url = dsn.envelope_api_url().to_string();

        let thread = TransportThread::new(move |envelope, mut rl| {
            let mut body = Vec::new();
            envelope.to_writer(&mut body).unwrap();

            let request = hyper::Request::builder()
                .header("X-Sentry-Auth", &auth)
                .method(Method::POST)
                .uri(&url)
                .body(Full::new(body.into()).boxed_unsync())
                .unwrap();

            // NOTE: because of lifetime issues, building the request using the
            // `client` has to happen outside of this async block.
            let client = client.clone();
            async move {
                match client.request(request).await {
                    Ok(response) => {
                        let headers = response.headers();

                        if let Some(sentry_header) = headers
                            .get("x-sentry-rate-limits")
                            .and_then(|x| x.to_str().ok())
                        {
                            rl.update_from_sentry_header(sentry_header);
                        } else if let Some(retry_after) = headers
                            .get(HyperHeaders::RETRY_AFTER)
                            .and_then(|x| x.to_str().ok())
                        {
                            rl.update_from_retry_after(retry_after);
                        } else if response.status() == StatusCode::TOO_MANY_REQUESTS {
                            rl.update_from_429();
                        }

                        match response.collect().await {
                            Err(err) => {
                                sentry_debug!("Failed to read sentry response: {}", err);
                            }
                            Ok(bytes) => {
                                let bytes = bytes.to_bytes();
                                let text = String::from_utf8_lossy(&bytes);
                                sentry_debug!("Get response: `{}`", text);
                            }
                        }
                    }
                    Err(err) => {
                        sentry_debug!("Failed to send envelope: {}", err);
                    }
                }
                rl
            }
        });
        Self { thread }
    }
}

impl Transport for HyperHttpTransport {
    fn send_envelope(&self, envelope: Envelope) {
        self.thread.send(envelope)
    }
    fn flush(&self, timeout: Duration) -> bool {
        self.thread.flush(timeout)
    }

    fn shutdown(&self, timeout: Duration) -> bool {
        self.flush(timeout)
    }
}
