use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct SignJson<'a> {
    pub status: &'a str,
    pub command: &'a str,
    pub input: String,
    pub output: String,
    pub key_fingerprint: String,
    pub uids: Vec<String>,
    pub embed_uid: bool,
}

#[derive(Serialize)]
pub(crate) struct VerifyJson<'a> {
    pub status: &'a str,
    pub command: &'a str,
    pub input: String,
    pub key_fingerprint: String,
    pub uids: Vec<String>,
    pub cert_source: &'a str,
    pub signatures: Vec<VerifySignatureJson>,
}

#[derive(Serialize)]
pub(crate) struct VerifySignatureJson {
    pub key_fingerprint: String,
    pub uids: Vec<String>,
    pub cert_source: String,
}

#[derive(Serialize)]
pub(crate) struct ErrorJson<'a> {
    pub status: &'a str,
    pub error: String,
    pub causes: Vec<String>,
}


