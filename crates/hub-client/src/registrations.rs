use alloy_primitives::{B256, Bytes};
use hub_domain::ConsensusPublicKey;
use hub_modules::acp::keys;
use hub_permission::{
    ModuleId, PAGE_PROOF_BYTES, PAGE_RESPONSE_BYTES, PrefixPageRequest, PrefixPageResponse,
};

use crate::{ClientError, HubClient};

/// Certified commitment identifiers at one revision; subsequent pages may select newer state.
#[derive(Clone, Debug)]
pub struct CommitmentIdPage {
    /// Finalized revision authenticating this page.
    pub revision: u64,
    /// Matching identifiers in ascending order.
    pub ids: Vec<u64>,
    /// Inclusive start for the next page.
    pub continuation: Option<Bytes>,
}

impl HubClient {
    /// Discover commitment IDs matching a root without scanning unrelated history.
    pub async fn read_registration_commitment_ids(
        &self,
        root: B256,
        cursor: Option<Bytes>,
        limit: u16,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<CommitmentIdPage, ClientError> {
        let prefix = Bytes::from(keys::commitment_by_commitment_index_prefix(root.as_slice()));
        let request = PrefixPageRequest {
            module: ModuleId::Acp,
            start: cursor.unwrap_or_else(|| prefix.clone()),
            prefix,
            limit,
        };
        request.validate()?;
        let response: PrefixPageResponse = self
            .rpc_call_bounded(
                "hub_getCurrentPrefixPageProof",
                serde_json::json!([request, minimum]),
                PAGE_RESPONSE_BYTES,
            )
            .await?;
        let page = response.verify(&request, minimum, trusted, PAGE_PROOF_BYTES)?;
        let ids = page
            .entries
            .iter()
            .map(|entry| decode_id(&request.prefix, &entry.key, &entry.value))
            .collect::<Result<_, _>>()?;
        Ok(CommitmentIdPage {
            revision: response.revision.height,
            ids,
            continuation: page.continuation,
        })
    }
}

fn decode_id(prefix: &[u8], key: &[u8], value: &[u8]) -> Result<u64, ClientError> {
    if !key.starts_with(prefix) || key.len() != prefix.len() + 8 || !value.is_empty() {
        return Err(ClientError::InvalidResponse(
            "invalid commitment root index",
        ));
    }
    let id = u64::from_be_bytes(
        key[prefix.len()..]
            .try_into()
            .map_err(|_| ClientError::InvalidResponse("invalid commitment identifier"))?,
    );
    if id == 0 {
        return Err(ClientError::InvalidResponse(
            "invalid commitment identifier",
        ));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commitment_id_decoding_binds_root_and_shape() {
        let root = [9; 32];
        let prefix = keys::commitment_by_commitment_index_prefix(&root);
        let key = keys::commitment_by_commitment_index_key(&root, 7);
        assert_eq!(decode_id(&prefix, &key, &[]).unwrap(), 7);
        assert!(decode_id(&prefix, &key, &[0]).is_err());
        assert!(decode_id(&prefix, &key[..key.len() - 1], &[]).is_err());
        assert!(
            decode_id(
                &prefix,
                &keys::commitment_by_commitment_index_key(&[8; 32], 7),
                &[]
            )
            .is_err()
        );
        assert!(
            decode_id(
                &prefix,
                &keys::commitment_by_commitment_index_key(&root, 0),
                &[]
            )
            .is_err()
        );
    }
}
