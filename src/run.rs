use crate::encoding::{pk_to_hex, sk_to_hex};
use crust::{
    BootstrapCacheConfig, Config, ConnectionInfoResult, CrustError, CrustUser, Event, PeerId,
    PrivConnectionInfo, Service,
};
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use rust_sodium::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
use safe_crypto::{gen_encrypt_keypair, PublicEncryptKey, PublicSignKey, SecretEncryptKey};
use serde_json::json;
use std::collections::HashSet;
use std::sync::mpsc::{channel, Receiver, RecvError, Sender};

/// generate a secret key on which to listen, print resultant keypair as json
pub fn generate() {
    let (enc_pk, enc_sk) = gen_encrypt_keypair();
    println!(
        "{}",
        json!({
            "secret": sk_to_hex(enc_sk),
            "public": pk_to_hex(enc_pk),
        })
    )
}

/// generate a secret on which to listen, print public key to stderr, listen on private key
pub fn gen_listen() {
    let (enc_pk, enc_sk) = gen_encrypt_keypair();
    eprintln!("{}", pk_to_hex(enc_pk));
    listen(enc_sk);
}

/// listen on private key. On connection, print recieved data, return when connection is closed
pub fn listen(private_key: SecretEncryptKey) {
    let (event_rx, event_category_rx, mut service) = make_service(private_key);
    service.start_listening_tcp();
    service.start_bootstrap(HashSet::new(), CrustUser::Node);

    // match event_category_rx.recv().unwrap() {
    //     MaidSafeEventCategory::Crust
    // }

    // let connection = service.get_first_connection().unwrap();
    // for packet in connection.iter() {
    //     stdout.write(packet.payload)
    // }
}

/// send data from stdin to host listening on public_key
pub fn gen_send(remote_pk: PublicEncryptKey) {
    let local_sk = gen_encrypt_keypair().1;
    send(remote_pk, local_sk)
}

/// send data from stdin to host listening on public_key. authenticate using local secret key
pub fn send(remote_pk: PublicEncryptKey, local_sk: SecretEncryptKey) {
    let remote_id = PeerId {
        pub_sign_key: PublicSignKey::from_bytes([0; 32]),
        pub_enc_key: remote_pk,
    };
    let (channel_rx, category_rx, mut service) = make_service(local_sk);
    service.start_bootstrap(HashSet::new(), CrustUser::Client);
    service.prepare_connection_info(1);

    let connection_info = get_connection_info(&mut service, &mut channel_rx);
    // Stuck here. How do we get connection info for another peer?
    // Do we need to bootstrap instead?
    service.connect(connection_info, );

    service.send(&remote_id, vec![0, 2, 4], 0).unwrap();
    // for data in stdin.iter() {
    //     service.send(remote_id, data, 0)
    // }
}

fn make_service(
    private_key: SecretEncryptKey,
) -> (Receiver<Event>, Receiver<MaidSafeEventCategory>, Service) {
    let (channel_sender, channel_receiver) = channel();
    let (category_tx, category_rx) = channel();
    let event_sender =
        MaidSafeObserver::new(channel_sender, MaidSafeEventCategory::Crust, category_tx);
    let our_id = PeerId {
        pub_sign_key: PublicSignKey::from_bytes([0; 32]),
        pub_enc_key: pub_from_priv(&private_key),
    };
    let service = Service::try_new(event_sender, our_id, private_key).unwrap();
    // let config = Config {
    //     hard_coded_contacts: vec![],
    //     tcp_acceptor_port: None,
    //     force_acceptor_port_in_ext_ep: false,
    //     service_discovery_port: None,
    //     service_discovery_listener_port: None,
    //     bootstrap_cache: BootstrapCacheConfig {
    //         file_name: None,
    //         max_size: 5000,
    //         timeout: 50000,
    //     },
    //     whitelisted_node_ips: None,
    //     whitelisted_client_ips: None,
    //     network_name: None,
    // };
    // let service = Service::with_config(event_sender, config, our_id, private_key).unwrap();
    (channel_receiver, category_rx, service)
}

fn pub_from_priv(private_key: &SecretEncryptKey) -> PublicEncryptKey {
    // get rust_sodium::crypto::box_::curve25519xsalsa20poly1305::SecretKey from private_key.
    let raw: [u8; 32] = private_key.clone().into_bytes();
    let primitive = SecretKey(raw);

    // Call fn public_key() to compute corresponding public key
    PublicEncryptKey::from_bytes(primitive.public_key().0)
}

fn get_connection_info(
    service: &mut Service,
    event_rx: &mut Receiver<Event>,
) -> Result<PrivConnectionInfo, CrustError> {
    service.prepare_connection_info(100);
    for event in event_rx.iter() {
        match event {
            Event::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token,
                result,
            }) => {
                return result;
            }
            _ => (),
        }
    }
    Err(CrustError::ChannelRecv(RecvError))
}
