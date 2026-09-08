//! Certified bulletin lifecycle, bounded enumeration and collaborator revocation.

use std::time::Duration;

use alloy_sol_types::SolCall;
use hub_client::{BULLETIN_ADDRESS, BlsSigner, HubClient};
use hub_domain::ConsensusPublicKey;
use hub_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use hub_modules::bulletin::{abi::IBulletin, keys};

async fn submit(
    client: &HubClient,
    observer: &HubClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: impl SolCall,
    success: bool,
) -> u64 {
    let wire = signer
        .sign_native_tx(BULLETIN_ADDRESS, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = observer.read_receipt(id, trusted).await.unwrap() {
                let receipt = proof.verify(id, trusted).unwrap();
                assert_eq!(receipt.success(), success, "{receipt:?}");
                break proof.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

fn post(namespace: &str, payload: &[u8]) -> IBulletin::createPostCall {
    IBulletin::createPostCall {
        namespace: namespace.into(),
        payload: payload.to_vec().into(),
        proof: vec![1, 2, 3].into(),
        artifact: String::new(),
    }
}

#[tokio::test]
async fn certified_bulletin_reads_follow_grants_pages_and_restart() {
    let deployment = 9065;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let observed = cluster.observe(Duration::from_millis(100));
    observed
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let writer = HubClient::new(cluster.node(0).rpc_url());
    let reader = HubClient::new(cluster.node(3).rpc_url());
    let owner = BlsSigner::new(7u64.into(), deployment).unwrap();
    let collaborator = BlsSigner::new(8u64.into(), deployment).unwrap();
    let absent = reader
        .read_bulletin_namespace("team", 0, &trusted)
        .await
        .unwrap();
    assert!(absent.value.is_none());
    assert!(
        reader
            .list_bulletin_namespaces(None, 1, absent.revision, &trusted)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    let mut minimum = submit(
        &writer,
        &reader,
        &owner,
        &trusted,
        IBulletin::registerNamespaceCall {
            namespace: "team".into(),
        },
        true,
    )
    .await;
    let namespace = reader
        .read_bulletin_namespace("team", minimum, &trusted)
        .await
        .unwrap();
    let namespace = namespace.value.unwrap();
    assert_eq!(namespace.id, "bulletin/team");
    assert_eq!(namespace.owner_did, owner.did());
    assert_eq!(namespace.created_at.block_height, minimum);
    let denied = b"before grant";
    minimum = submit(
        &writer,
        &reader,
        &collaborator,
        &trusted,
        post("team", denied),
        false,
    )
    .await;
    assert!(
        reader
            .read_bulletin_post(
                "team",
                &keys::generate_post_id("bulletin/team", denied),
                minimum,
                &trusted
            )
            .await
            .unwrap()
            .value
            .is_none()
    );
    minimum = submit(
        &writer,
        &reader,
        &owner,
        &trusted,
        IBulletin::addCollaboratorCall {
            namespace: "team".into(),
            collaboratorDid: collaborator.did().into(),
        },
        true,
    )
    .await;
    assert_eq!(
        reader
            .read_bulletin_collaborator("team", collaborator.did(), minimum, &trusted)
            .await
            .unwrap()
            .value
            .unwrap()
            .did,
        collaborator.did()
    );
    let collaborators = reader
        .list_bulletin_collaborators("team", None, 1, minimum, &trusted)
        .await
        .unwrap();
    assert_eq!(collaborators.records.len(), 1);
    assert!(collaborators.continuation.is_none());
    for payload in [b"first".as_slice(), b"second"] {
        minimum = submit(
            &writer,
            &reader,
            &collaborator,
            &trusted,
            post("team", payload),
            true,
        )
        .await;
        let record = reader
            .read_bulletin_post(
                "team",
                &keys::generate_post_id("bulletin/team", payload),
                minimum,
                &trusted,
            )
            .await
            .unwrap()
            .value
            .unwrap();
        assert_eq!(record.payload, payload);
        assert_eq!(record.proof, [1, 2, 3]);
        assert_eq!(record.creator_did, collaborator.did());
    }
    let first = reader
        .list_bulletin_posts("team", None, 1, minimum, &trusted)
        .await
        .unwrap();
    assert_eq!(first.records.len(), 1);
    let next = first.continuation.unwrap();
    assert!(
        reader
            .list_bulletin_posts("other", Some(next.clone()), 1, minimum, &trusted)
            .await
            .is_err()
    );
    let last = reader
        .list_bulletin_posts("team", Some(next), 1, first.revision, &trusted)
        .await
        .unwrap();
    assert_eq!(last.records.len(), 1);
    assert!(last.continuation.is_none());
    assert!(first.records[0].id < last.records[0].id);
    minimum = submit(
        &writer,
        &reader,
        &owner,
        &trusted,
        IBulletin::removeCollaboratorCall {
            namespace: "team".into(),
            collaboratorDid: collaborator.did().into(),
        },
        true,
    )
    .await;
    assert!(
        reader
            .read_bulletin_collaborator("team", collaborator.did(), minimum, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    assert!(
        reader
            .list_bulletin_collaborators("team", None, 1, minimum, &trusted)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    minimum = submit(
        &writer,
        &reader,
        &collaborator,
        &trusted,
        post("team", b"after revocation"),
        false,
    )
    .await;
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let restored = reader
        .list_bulletin_posts("team", None, 2, minimum, &trusted)
        .await
        .unwrap();
    assert_eq!(
        restored.records,
        [first.records[0].clone(), last.records[0].clone()]
    );
    assert!(restored.continuation.is_none());
    assert!(
        reader
            .read_bulletin_collaborator("team", collaborator.did(), minimum, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let untrusted = *KeySet::builder()
        .seed(deployment + 1)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    assert!(
        reader
            .read_bulletin_namespace("team", minimum, &untrusted)
            .await
            .is_err()
    );
}
