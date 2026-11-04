//! bbiot-mls — an MLS (RFC 9420) sidecar built on OpenMLS.
//!
//! Runs as a subprocess inside ONE device's container; its MLS secrets never
//! leave that process. It speaks JSON lines on stdin/stdout:
//!
//!   -> {"id": 1, "cmd": "init", "identity": "phone", "sig_priv": "..hex..", "sig_pub": "..hex.."}
//!   <- {"id": 1, "ok": true, "result": {...}}      or   {"id": 1, "ok": false, "error": "..."}
//!
//! The MLS signature key is the device's own Ed25519 identity key (the one in its
//! root-signed X.509 certificate), so every key package, commit and welcome is
//! bound to a certified identity. Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
//!
//! The group key used for application messages is derived with the MLS exporter
//! (`export`), so the device's message layer is unchanged between modes.

use std::io::{self, BufRead, Write};

use anyhow::{anyhow, bail, Context, Result};
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{json, Value};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct State {
    provider: OpenMlsRustCrypto,
    identity: String,
    signer: Option<SignatureKeyPair>,
    credential: Option<CredentialWithKey>,
    group: Option<MlsGroup>,
}

fn hex_arg(v: &Value, key: &str) -> Result<Vec<u8>> {
    let s = v.get(key).and_then(Value::as_str).ok_or_else(|| anyhow!("missing '{key}'"))?;
    hex::decode(s).with_context(|| format!("'{key}' is not hex"))
}

fn str_arg<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or_else(|| anyhow!("missing '{key}'"))
}

fn identity_of(credential: &Credential) -> String {
    BasicCredential::try_from(credential.clone())
        .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
        .unwrap_or_else(|_| "?".into())
}

fn ser(msg: &MlsMessageOut) -> Result<String> {
    Ok(hex::encode(msg.tls_serialize_detached()?))
}

fn parse_msg(bytes: &[u8]) -> Result<MlsMessageBodyIn> {
    Ok(MlsMessageIn::tls_deserialize_exact(bytes)?.extract())
}

impl State {
    /// Forget the current group, including its persisted state in the provider's
    /// storage (otherwise re-joining the same group later fails).
    fn drop_group(&mut self) -> Result<()> {
        if let Some(mut g) = self.group.take() {
            g.delete(self.provider.storage())
                .map_err(|e| anyhow!("could not delete old group state: {e:?}"))?;
        }
        Ok(())
    }

    fn signer(&self) -> Result<&SignatureKeyPair> {
        self.signer.as_ref().ok_or_else(|| anyhow!("not initialised"))
    }

    fn group(&self) -> Result<&MlsGroup> {
        self.group.as_ref().ok_or_else(|| anyhow!("not in a group"))
    }

    fn members_json(&self) -> Result<Value> {
        let g = self.group()?;
        let members: Vec<Value> = g
            .members()
            .map(|m| {
                json!({
                    "index": m.index.u32(),
                    "identity": identity_of(&m.credential),
                    "signature_key": hex::encode(&m.signature_key),
                })
            })
            .collect();
        Ok(json!({
            "group_id": hex::encode(g.group_id().as_slice()),
            "epoch": g.epoch().as_u64(),
            "own_index": g.own_leaf_index().u32(),
            "members": members,
        }))
    }

    fn handle(&mut self, req: &Value) -> Result<Value> {
        match str_arg(req, "cmd")? {
            "init" => {
                let identity = str_arg(req, "identity")?.to_string();
                let private = hex_arg(req, "sig_priv")?;
                let public = hex_arg(req, "sig_pub")?;
                let signer = SignatureKeyPair::from_raw(
                    CIPHERSUITE.signature_algorithm(),
                    private,
                    public.clone(),
                );
                signer.store(self.provider.storage())?;
                let credential = BasicCredential::new(identity.clone().into_bytes());
                self.credential = Some(CredentialWithKey {
                    credential: credential.into(),
                    signature_key: public.into(),
                });
                self.identity = identity;
                self.signer = Some(signer);
                self.drop_group()?;
                Ok(json!({"identity": self.identity, "ciphersuite": format!("{CIPHERSUITE:?}")}))
            }

            "key_package" => {
                let cred = self.credential.clone().ok_or_else(|| anyhow!("not initialised"))?;
                let bundle =
                    KeyPackage::builder().build(CIPHERSUITE, &self.provider, self.signer()?, cred)?;
                let kp = bundle.key_package().clone();
                Ok(json!({"key_package": hex::encode(kp.tls_serialize_detached()?)}))
            }

            // Validate a key package someone else published (signature, lifetime,
            // ciphersuite) and return who it claims to be and which key signed it.
            "inspect_key_package" => {
                let kp = KeyPackageIn::tls_deserialize_exact(hex_arg(req, "key_package")?.as_slice())?
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| anyhow!("key package invalid: {e:?}"))?;
                let leaf = kp.leaf_node();
                Ok(json!({
                    "identity": identity_of(leaf.credential()),
                    "signature_key": hex::encode(leaf.signature_key().as_slice()),
                }))
            }

            "create_group" => {
                let cred = self.credential.clone().ok_or_else(|| anyhow!("not initialised"))?;
                let config = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .use_ratchet_tree_extension(true)
                    .build();
                let gid = GroupId::from_slice(&hex_arg(req, "group_id")?);
                self.drop_group()?;
                let group =
                    MlsGroup::new_with_group_id(&self.provider, self.signer()?, &config, gid, cred)?;
                self.group = Some(group);
                self.members_json()
            }

            "add" => {
                let kps: Vec<KeyPackage> = req
                    .get("key_packages")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("missing 'key_packages'"))?
                    .iter()
                    .map(|v| {
                        let bytes = hex::decode(v.as_str().unwrap_or_default())?;
                        KeyPackageIn::tls_deserialize_exact(bytes.as_slice())?
                            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                            .map_err(|e| anyhow!("key package invalid: {e:?}"))
                    })
                    .collect::<Result<_>>()?;
                let signer = self.signer.take().ok_or_else(|| anyhow!("not initialised"))?;
                let provider = &self.provider;
                let result = (|| -> Result<(String, String)> {
                    let g = self.group.as_mut().ok_or_else(|| anyhow!("not in a group"))?;
                    let (commit, welcome, _info) = g.add_members(provider, &signer, &kps)?;
                    g.merge_pending_commit(provider)?;
                    Ok((ser(&commit)?, ser(&welcome)?))
                })();
                self.signer = Some(signer);
                let (commit, welcome) = result?;
                let mut out = self.members_json()?;
                out["commit"] = json!(commit);
                out["welcome"] = json!(welcome);
                Ok(out)
            }

            "remove" => {
                let wanted: Vec<String> = req
                    .get("identities")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("missing 'identities'"))?
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                let indices: Vec<LeafNodeIndex> = self
                    .group()?
                    .members()
                    .filter(|m| wanted.contains(&identity_of(&m.credential)))
                    .map(|m| m.index)
                    .collect();
                if indices.is_empty() {
                    bail!("none of {wanted:?} are members");
                }
                let signer = self.signer.take().ok_or_else(|| anyhow!("not initialised"))?;
                let provider = &self.provider;
                let result = (|| -> Result<String> {
                    let g = self.group.as_mut().ok_or_else(|| anyhow!("not in a group"))?;
                    let (commit, _welcome, _info) = g.remove_members(provider, &signer, &indices)?;
                    g.merge_pending_commit(provider)?;
                    ser(&commit)
                })();
                self.signer = Some(signer);
                let mut out = self.members_json()?;
                out["commit"] = json!(result?);
                Ok(out)
            }

            // Rekey without a membership change: a self-update commit gives the
            // group fresh secrets (new epoch). Used by the benchmarks.
            "update" => {
                let signer = self.signer.take().ok_or_else(|| anyhow!("not initialised"))?;
                let provider = &self.provider;
                let result = (|| -> Result<String> {
                    let g = self.group.as_mut().ok_or_else(|| anyhow!("not in a group"))?;
                    let bundle = g.self_update(provider, &signer, LeafNodeParameters::default())?;
                    g.merge_pending_commit(provider)?;
                    ser(bundle.commit())
                })();
                self.signer = Some(signer);
                let mut out = self.members_json()?;
                out["commit"] = json!(result?);
                Ok(out)
            }

            "welcome" => {
                let welcome = match parse_msg(&hex_arg(req, "welcome")?)? {
                    MlsMessageBodyIn::Welcome(w) => w,
                    _ => bail!("not a Welcome message"),
                };
                // Replacing whatever group we had (e.g. after being removed and re-added).
                self.drop_group()?;
                let config = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
                let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
                    .map_err(|e| anyhow!("welcome rejected: {e:?}"))?;
                let group = staged
                    .into_group(&self.provider)
                    .map_err(|e| anyhow!("welcome rejected: {e:?}"))?;
                self.group = Some(group);
                self.members_json()
            }

            // Process a commit from another member. Returns who committed it, so
            // the caller can enforce who is allowed to change the group.
            "commit" => {
                let protocol: ProtocolMessage = match parse_msg(&hex_arg(req, "commit")?)? {
                    MlsMessageBodyIn::PublicMessage(m) => m.into(),
                    MlsMessageBodyIn::PrivateMessage(m) => m.into(),
                    _ => bail!("not a handshake message"),
                };
                let provider = &self.provider;
                let g = self.group.as_mut().ok_or_else(|| anyhow!("not in a group"))?;
                let processed = g
                    .process_message(provider, protocol)
                    .map_err(|e| anyhow!("commit rejected: {e:?}"))?;
                let committer = identity_of(processed.credential());
                let staged = match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(s) => s,
                    _ => bail!("not a commit"),
                };
                let removed_self = staged.self_removed();
                let expected = req.get("expected_committer").and_then(Value::as_str);
                if let Some(expected) = expected {
                    if committer != expected {
                        // Discard: don't merge a commit from an unauthorised member.
                        bail!("commit by '{committer}' refused (only '{expected}' may change the group)");
                    }
                }
                g.merge_staged_commit(provider, *staged)?;
                if removed_self {
                    self.drop_group()?;
                    return Ok(json!({"removed": true, "committer": committer}));
                }
                let mut out = self.members_json()?;
                out["committer"] = json!(committer);
                Ok(out)
            }

            "export" => {
                let label = str_arg(req, "label")?;
                let length = req.get("length").and_then(Value::as_u64).unwrap_or(32) as usize;
                let g = self.group()?;
                let secret = g.export_secret(self.provider.crypto(), label, &[], length)?;
                Ok(json!({"epoch": g.epoch().as_u64(), "secret": hex::encode(secret)}))
            }

            "members" => self.members_json(),

            "status" => Ok(match &self.group {
                Some(g) => json!({"in_group": true, "epoch": g.epoch().as_u64(),
                                  "group_id": hex::encode(g.group_id().as_slice())}),
                None => json!({"in_group": false}),
            }),

            "leave" => {
                self.drop_group()?;
                Ok(json!({"in_group": false}))
            }

            other => bail!("unknown command '{other}'"),
        }
    }
}

fn main() -> Result<()> {
    let mut state = State {
        provider: OpenMlsRustCrypto::default(),
        identity: String::new(),
        signer: None,
        credential: None,
        group: None,
    };
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let id = req.get("id").cloned().unwrap_or(Value::Null);
                match state.handle(&req) {
                    Ok(result) => json!({"id": id, "ok": true, "result": result}),
                    Err(e) => json!({"id": id, "ok": false, "error": format!("{e:#}")}),
                }
            }
            Err(e) => json!({"id": null, "ok": false, "error": format!("bad request: {e}")}),
        };
        writeln!(stdout, "{reply}")?;
        stdout.flush()?;
    }
    Ok(())
}
