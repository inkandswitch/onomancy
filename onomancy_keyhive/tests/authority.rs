//! End-to-end: an owner-side Keyhive builds a REAL delegation graph,
//! exports it as carriage events, and [`KeyhiveAuthority`] verifies
//! signers against it — the checks that were vacuous under the
//! permissive memory fake, exercised for real.

use ed25519_dalek::{SigningKey, VerifyingKey};
use future_form::Sendable;
use futures::executor::block_on;
use keyhive_core::{
    access::Access,
    event::{Event, static_event::StaticEvent},
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::{identifier::Identifier, individual::op::KeyOp, membered::Membered},
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::signer::memory::MemorySigner;
use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain};
use onomancy_dnssec::txt::generation_key::GenerationKey;
use onomancy_keyhive::{authority::KeyhiveAuthority, carriage::Carriage};
use onomancy_protocol::verifier::state::authority_verifier::AuthorityVerifier;
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
    carriage: onomancy_core::delegation_chain::DelegationChain,
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
        KeyhiveAuthority.authorizes(
            &f.anchor,
            f.anchor.verifying_key(),
            &DelegationChain::default()
        ),
        "identity rule: the document root key needs no chain"
    );

    // The identity rule short-circuits BEFORE replay — deliberate
    // (authority.rs module docs): a signer that IS the root has
    // nothing to prove, so even a garbage carriage cannot demote it.
    let garbage = DelegationChain::from(vec![
        onomancy_core::delegation_chain::SignedDelegationBytes::from(b"zz9garbage".to_vec()),
    ]);
    assert!(
        KeyhiveAuthority.authorizes(&f.anchor, f.anchor.verifying_key(), &garbage),
        "the short-circuit precedes carriage parsing, by design"
    );
    Ok(())
}

/// The signing bar's REJECTION direction (dns-anchor §Who Signs): a
/// signer who is a genuine DIRECT member of the root group, whose
/// delegating hop holds LESS than Admin, is refused. This is the
/// only test the access comparison itself protects: `sanctioned`
/// finds the signer among the root's members (no absence, no
/// depth-2 gap), reads the delegating hop's proof (`can = Edit`),
/// and the bar refuses it. Weakening the bar to `>= Access::Read` —
/// or deleting the access check — fails here and nowhere else.
#[test]
#[allow(clippy::too_many_lines)] // two instances must exchange a real graph
fn sub_admin_delegating_hops_fail_the_signing_bar() -> TestResult {
    let built = block_on(async {
        let owner = instance().await?;
        let deputy = instance().await?;
        let signer = instance().await?;

        let root = owner.generate_group(vec![]).await?;
        let root_id = { root.lock().await.group_id() };
        let anchor = DocAnchor::from(Identifier::from(root_id).0);

        // root ──Edit──▶ deputy: the sub-Admin hop.
        let deputy_card = deputy.contact_card().await?;
        owner.receive_contact_card(&deputy_card).await?;
        let deputy_agent = owner
            .get_agent(Identifier::from(deputy_card.id()))
            .await
            .ok_or("just introduced")?;
        owner
            .add_member(
                deputy_agent,
                &Membered::Group(root_id, root.clone()),
                Access::Edit,
                &[],
            )
            .await?;

        // The deputy materializes the group from the owner's export.
        // Retried to a fixpoint: export order is dependency-
        // compatible, not dependency-sorted — the same discipline the
        // verifier's replay uses.
        let mut remaining: Vec<StaticEvent<[u8; 32]>> = Vec::new();
        for ops in owner
            .reachable_prekey_ops_for_all_agents()
            .await
            .ops
            .values()
        {
            for op in ops {
                remaining.push(prekey_event(op));
            }
        }
        for op_map in owner.membership_ops_for_all_agents().await.ops.values() {
            for op in op_map.values() {
                let event: Event<_, _, _, _> = op.clone().into();
                remaining.push(event.into());
            }
        }
        loop {
            let mut deferred = Vec::with_capacity(remaining.len());
            for event in remaining.drain(..) {
                if deputy.receive_static_event(event.clone()).await.is_err() {
                    deferred.push(event);
                }
            }
            match (deferred.is_empty(), deferred.len() == deferred.capacity()) {
                (true, _) => break,
                (false, true) => return Err("deputy ingest stalled".into()),
                (false, false) => remaining = deferred,
            }
        }

        // …and adds the signer DIRECTLY to the root group. The
        // signer's delegation proof is the deputy's own Edit-access
        // delegation — the sub-Admin delegating hop §Who Signs bars.
        let signer_card = signer.contact_card().await?;
        deputy.receive_contact_card(&signer_card).await?;
        let signer_agent = deputy
            .get_agent(Identifier::from(signer_card.id()))
            .await
            .ok_or("just introduced to the deputy")?;
        let root_at_deputy = deputy
            .get_group(root_id)
            .await
            .ok_or("the deputy holds the group")?;
        deputy
            .add_member(
                signer_agent,
                &Membered::Group(root_id, root_at_deputy),
                Access::Read,
                &[],
            )
            .await?;

        let signer_key = Identifier::from(signer_card.id()).0;

        // The carriage is the DEPUTY's view: it holds the owner's
        // ops plus its own delegation of the signer — and the
        // delegates' introductions, which live in their contact-card
        // ops and ride no all-agents export.
        let mut events: Vec<StaticEvent<[u8; 32]>> = Vec::new();
        events.push(prekey_event(deputy_card.op()));
        events.push(prekey_event(signer_card.op()));
        for ops in deputy
            .reachable_prekey_ops_for_all_agents()
            .await
            .ops
            .values()
        {
            for op in ops {
                events.push(prekey_event(op));
            }
        }
        for op_map in deputy.membership_ops_for_all_agents().await.ops.values() {
            for op in op_map.values() {
                let event: Event<_, _, _, _> = op.clone().into();
                events.push(event.into());
            }
        }

        Ok::<_, testresult::TestError>((
            anchor,
            signer_key,
            Carriage::new(events).to_delegation_bytes()?,
        ))
    })?;
    let (anchor, signer_key, carriage) = built;

    // Sanity: the signer IS in the graph — the refusal below is the
    // access bar, never absence.
    assert!(
        KeyhiveAuthority.on_path(&carriage, &GenerationKey::from(signer_key)),
        "the signer is a genuine (direct) member of the root group"
    );

    assert!(
        !KeyhiveAuthority.authorizes(&anchor, &signer_key, &carriage),
        "a delegating hop below Admin fails the signing bar"
    );
    Ok(())
}

/// The replay's no-progress fixpoint, specifically: a carriage whose
/// delegation names a key the (dropped) prekey introduction would
/// have introduced can never fully ingest — the replay refuses,
/// rather than looping or accepting a partial graph.
#[test]
fn dangling_dependencies_refuse_at_the_fixpoint() -> TestResult {
    let doc_key = SigningKey::from_bytes(&[11; 32]);
    let generation_key = SigningKey::from_bytes(&[12; 32]);
    let minted = onomancy_keyhive::mint::generation_carriage(&doc_key, &generation_key)?;

    // Drop the prekey introduction (entry 0), keeping the delegation
    // that depends on it. Every entry still PARSES — the refusal is
    // the ingest fixpoint, not the envelope.
    let entries = minted.entries().to_vec();
    let dangling = DelegationChain::from(entries.get(1..).ok_or("two entries")?.to_vec());
    assert_eq!(dangling.len(), 1);

    let generation = GenerationKey::from(generation_key.verifying_key());
    assert!(
        KeyhiveAuthority.on_path(&minted, &generation),
        "the complete carriage proves the path"
    );
    assert!(
        !KeyhiveAuthority.on_path(&dangling, &generation),
        "dropping the introduction dangles the delegation: refused"
    );
    Ok(())
}

#[test]
fn tampered_carriages_prove_nothing() -> TestResult {
    let f = block_on(fixture())?;

    let mut entries = f.carriage.entries().to_vec();
    let mut bytes = entries.pop().ok_or("nonempty")?.as_bytes().to_vec();
    *bytes.last_mut().ok_or("nonempty entry")? ^= 0xFF;
    entries.push(bytes.into());
    let tampered = DelegationChain::from(entries);

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
        !KeyhiveAuthority.on_path(&DelegationChain::default(), &unknown_generation),
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
        !KeyhiveAuthority.vouches_document(&anchor, &DelegationChain::default()),
        "an empty carriage vouches nothing"
    );
    Ok(())
}

/// A nested graph: `root` delegates Admin to an intermediate `team`
/// group, and `team` delegates to `member`. The signer is two hops
/// from the root and is not a direct member of it.
///
/// This is the topology §Generation Key describes — *"an organization
/// MAY interpose a dedicated generation key over its cert-signing
/// members"* — and the shape a `AccessEditor`-style UI produces when a
/// user grants a *team* admin over their document.
struct Nested {
    anchor: DocAnchor,
    member_key: VerifyingKey,
    carriage: DelegationChain,
}

async fn nested_fixture() -> TestResult<Nested> {
    use keyhive_core::principal::agent::Agent;

    let owner = instance().await?;
    let member = instance().await?;

    let root = owner.generate_group(vec![]).await?;
    let root_id = { root.lock().await.group_id() };
    let anchor = DocAnchor::from(Identifier::from(root_id).0);

    let team = owner.generate_group(vec![]).await?;
    let team_id = { team.lock().await.group_id() };

    let mut events: Vec<StaticEvent<[u8; 32]>> = Vec::new();

    // root --Admin--> team
    owner
        .add_member(
            Agent::Group(team_id, team.clone()),
            &Membered::Group(root_id, root.clone()),
            Access::Admin,
            &[],
        )
        .await?;

    // team --Admin--> member
    let card = member.contact_card().await?;
    owner.receive_contact_card(&card).await?;
    events.push(prekey_event(card.op()));

    let agent = owner
        .get_agent(Identifier::from(card.id()))
        .await
        .ok_or("just introduced")?;
    owner
        .add_member(agent, &Membered::Group(team_id, team), Access::Admin, &[])
        .await?;

    let member_key = Identifier::from(member.contact_card().await?.id()).0;

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

    Ok(Nested {
        anchor,
        member_key,
        carriage: Carriage::new(events).to_delegation_bytes()?,
    })
}

#[test]
fn a_signer_delegated_through_a_group_is_on_the_path() -> TestResult {
    // `on_path` walks transitively and finds the member at depth 2.
    let f = block_on(nested_fixture())?;

    assert!(
        KeyhiveAuthority.on_path(&f.carriage, &GenerationKey::from(f.member_key)),
        "path membership is 'at any depth' (dns-anchor §Generation Key)"
    );
    Ok(())
}

#[test]
#[ignore = "known gap: `sanctioned` is direct-membership only \
            (authority.rs: 'naming chains through nested group \
            intermediaries are future work'). Un-ignore when it walks \
            transitively."]
fn a_signer_delegated_through_a_group_is_authorized() -> TestResult {
    // The gap, executable. §Generation Key describes signers sitting
    // below an interposed group; §Who Signs requires only that the
    // signer hold admin in the delegation chain, with no depth
    // qualifier. `sanctioned` looks only at the root's DIRECT members,
    // so this correctly-configured signer is refused.
    //
    // Note the asymmetry with the test above: the same carriage, the
    // same key, `on_path` true and `authorizes` false.
    let f = block_on(nested_fixture())?;

    assert!(
        KeyhiveAuthority.authorizes(&f.anchor, &f.member_key, &f.carriage),
        "an admin delegated through an intermediate group is still an admin"
    );
    Ok(())
}
