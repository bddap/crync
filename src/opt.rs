use crate::encoding::{pk_from_hex, sk_from_hex};
use crate::run::{gen_listen, gen_send, generate, listen, send};
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
use std::string::ToString;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "crync",
    about = "Super-powered, nat-hole punching version of netcat."
)]
pub enum Opt {
    #[structopt(name = "listen")]
    Listen {
        #[structopt(parse(try_from_str = "sk_from_hex"))]
        private_key: SecretEncryptKey,
    },
    #[structopt(name = "send")]
    Send {
        #[structopt(parse(try_from_str = "pk_from_hex"))]
        remote_public_key: PublicEncryptKey,
        #[structopt(parse(try_from_str = "sk_from_hex"))]
        private_key: SecretEncryptKey,
    },
    #[structopt(name = "gen")]
    Generate,
    #[structopt(name = "genlisten")]
    GenListen,
    #[structopt(name = "gensend")]
    GenSend {
        #[structopt(parse(try_from_str = "pk_from_hex"))]
        remote_public_key: PublicEncryptKey,
    },
}

impl Opt {
    pub fn run(self) {
        match self {
            Opt::Listen { private_key } => listen(private_key),
            Opt::Send {
                remote_public_key,
                private_key,
            } => send(remote_public_key, private_key),
            Opt::Generate => generate(),
            Opt::GenListen => gen_listen(),
            Opt::GenSend { remote_public_key } => gen_send(remote_public_key),
        }
    }
}
