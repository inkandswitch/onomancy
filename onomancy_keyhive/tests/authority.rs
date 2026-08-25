//! End-to-end: an owner-side Keyhive builds a REAL delegation graph,
//! exports it as carriage events, and [`KeyhiveAuthority`] verifies
//! signers against it — the checks that were vacuous under the
//! permissive memory fake, exercised for real.

use ed25519_dalek::{SigningKey, VerifyingKey};
use future_form::Sendable;
use futures::executor::block_on;
use keyhive_core::{
    access::Access,
    event::{static_event::StaticEvent, Event},
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{identifier::Identifier, individual::op::KeyOp, membered::Membered},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::signer::memory::MemorySigner;
use onomancy_core::{name::doc::DocAnchor, txt::generation_key::GenerationKey};
use onomancy_keyhive::{authority::KeyhiveAuthority, carriage::Carriage};
use onomancy_protocol::verifier_state::seam::AuthorityVerifier;
use rand::rngs::OsRng;
use testresult::TestResult;

type Instance = Keyhive<
    Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    OsRng,
>;

async fn instance() -> Result<Instance, keyhive_crypto::signed::SigningError> {
    Instance::generate(
        MemorySigner::generate(&mut OsRng),
        MemoryCiphertextStore::new(),
        NoListener,
        OsRng,
    )
    .await
}

/// A real graph: `owner` creates a group (the "document root"), then
/// delegates to `admin` at Admin and `reader` at Read access.
struct Fixture {
    anchor: DocAnchor,
    admin_key: VerifyingKey,
    reader_key: VerifyingKey,
    carriage: Vec<onomancy_core::delegation::DelegationBytes>,
}

fn prekey_event(op: &KeyOp) -> StaticEvent<[u8; 32]> {
    match op {
        KeyOp::Add(add) => StaticEvent::PrekeysExpanded(Box::new((**add).clone())),
        KeyOp::Rotate(rotate) => StaticEvent::PrekeyRotated(Box::new((**rotate).clone())),
    }
}

async fn fixture() -> TestResult<Fixture> {
    let owner = instance().await?;
    let admin = instance().await?;
    let reader = instance().await?;

    let group = owner.generate_group(vec![]).await?;
    let group_id = { group.lock().await.group_id() };
    let anchor = DocAnchor::from(Identifier::from(group_id).0);

    // Introduce both delegates to the owner via contact cards, then
    // delegate. Keep the card ops: a delegate's introduction lives in
    // their contact-card op, which no all-agents export carries — a
    // complete standalone proof must ship it explicitly.
    let mut events: Vec<StaticEvent<[u8; 32]>> = Vec::new();

    for (peer, access) in [(&admin, Access::Admin), (&reader, Access::Read)] {
        let card = peer.contact_card().await?;
        owner.receive_contact_card(&card).await?;
        events.push(prekey_event(card.op()));

        let agent = owner
            .get_agent(Identifier::from(card.id()))
            .await
            .ok_or("just introduced")?;
        owner
            .add_member(
                agent,
                &Membered::Group(group_id, group.clone()),
                access,
                &[],
            )
            .await?;
    }

    let admin_key = Identifier::from(admin.contact_card().await?.id()).0;
    let reader_key = Identifier::from(reader.contact_card().await?.id()).0;

    // Plus every membership op and the ISSUERS' reachable prekey
    // introductions. Duplicates are harmless — ingestion is
    // idempotent.
    for ops in owner
        .reachable_prekey_ops_for_all_agents()
        .await
        .ops
        .values()
    {
        for op in ops {
            events.push(prekey_event(op));
        }
    }

    for op_map in owner.membership_ops_for_all_agents().await.ops.values() {
        for op in op_map.values() {
            let event: Event<_, _, _, _> = op.clone().into();
            events.push(event.into());
        }
    }

    let carriage = Carriage::new(events).to_delegation_bytes()?;

    Ok(Fixture {
        anchor,
        admin_key,
        reader_key,
        carriage,
    })
}

#[test]
fn delegated_admins_are_authorized() -> TestResult {
    let f = block_on(fixture())?;

    assert!(
        KeyhiveAuthority.authorizes(&f.anchor, &f.admin_key, &f.carriage),
        "an Admin delegate must be authorized to speak for the document"
    );
    Ok(())
}

#[test]
fn admin_granted_delegates_sign_at_any_access() -> TestResult {
    // The signing bar is the DELEGATING hop, not the signer's rank
    // (dns-anchor §Who Signs): a Read delegate granted by an admin
    // clears it — the same rule that lets successor generation keys
    // sign rotation statements. Leak analysis in design/security.md.
    let f = block_on(fixture())?;

    assert!(
        KeyhiveAuthority.authorizes(&f.anchor, &f.reader_key, &f.carriage),
        "an admin-granted delegate clears the signing bar at any access"
    );
    Ok(())
}

#[test]
fn strangers_are_refused() -> TestResult {
    let f = block_on(fixture())?;
    let stranger = *ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .verifying_key()
        .as_bytes();
    let stranger = VerifyingKey::from_bytes(&stranger)?;

    assert!(
        !KeyhiveAuthority.authorizes(&f.anchor, &stranger, &f.carriage),
        "a key absent from the graph proves nothing"
    );
    Ok(())
}

#[test]
fn the_root_key_speaks_for_itself() -> TestResult {
    let f = block_on(fixture())?;

    assert!(
        KeyhiveAuthority.authorizes(&f.anchor, f.anchor.verifying_key(), &[]),
        "identity rule: the document root key needs no chain"
    );
    Ok(())
}

#[test]
fn tampered_carriages_prove_nothing() -> TestResult {
    let f = block_on(fixture())?;

    let mut tampered = f.carriage.clone();
    let mut bytes = tampered.pop().ok_or("nonempty")?.as_bytes().to_vec();
    *bytes.last_mut().ok_or("nonempty entry")? ^= 0xFF;
    tampered.push(bytes.into());

    assert!(
        !KeyhiveAuthority.authorizes(&f.anchor, &f.admin_key, &tampered),
        "one flipped byte must sink the whole proof"
    );
    Ok(())
}

#[test]
fn delegated_keys_are_on_path_at_any_access() -> TestResult {
    let f = block_on(fixture())?;

    let reader_generation = GenerationKey::from(f.reader_key);
    let unknown_generation =
        GenerationKey::from(ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key());

    assert!(
        KeyhiveAuthority.on_path(&f.carriage, &reader_generation),
        "any delegated key is on the path, even below Admin"
    );
    assert!(
        !KeyhiveAuthority.on_path(&f.carriage, &unknown_generation),
        "an undelegated key is off the path"
    );
    assert!(
        !KeyhiveAuthority.on_path(&[], &unknown_generation),
        "an empty carriage puts nothing on the path"
    );
    Ok(())
}

#[test]
fn document_carriages_vouch_their_anchor_and_nothing_else() -> TestResult {
    use onomancy_keyhive::mint::document_carriage;

    let doc_key = SigningKey::from_bytes(&[7; 32]);
    let anchor = DocAnchor::from(doc_key.verifying_key());
    let other = DocAnchor::from(SigningKey::from_bytes(&[8; 32]).verifying_key());

    let carriage = document_carriage(&doc_key)?;

    assert!(
        KeyhiveAuthority.vouches_document(&anchor, &carriage),
        "a minted carriage roots at its own document"
    );
    assert!(
        !KeyhiveAuthority.vouches_document(&other, &carriage),
        "and vouches no other anchor"
    );
    assert!(
        !KeyhiveAuthority.vouches_document(&anchor, &[]),
        "an empty carriage vouches nothing"
    );
    Ok(())
}
