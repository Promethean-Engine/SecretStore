use crate::types::EncryptedDocumentKey;
use codec::{Decode, Encode};

#[derive(Default, Debug, PartialEq, Encode, Decode)]
pub struct PermissionDatabase {
    permission_entries: Vec<PermissionEntry>,
    documents: Vec<Document>,
}

#[derive(Default, Debug, PartialEq, Encode, Decode, Clone)]
struct PermissionEntry {
    pub allowed_account: u64,
    pub document_id: Vec<u64>,
}

#[derive(Default, Debug, PartialEq, Encode, Decode, Clone)]
struct Document {
    pub id: u64,
    pub key: EncryptedDocumentKey,
}

impl PermissionDatabase {
    pub fn new() -> Self {
        PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
        }
    }

    fn get_if_address_allowed(&self, address: u64, document_id: u64) -> Option<&PermissionEntry> {
        let intermediate_list: Vec<&PermissionEntry> = self
            .permission_entries
            .iter()
            .filter(|item| {
                item.allowed_account == address
                    && item.document_id.iter().find(|x| x == &&document_id) != None
            })
            .collect();
        if !intermediate_list.is_empty() {
            Some(intermediate_list[0])
        } else {
            None
        }
    }

    pub fn get_encrypted_document_key(
        &self,
        address: u64,
        document_id: u64,
    ) -> Option<&EncryptedDocumentKey> {
        let retval: Option<&EncryptedDocumentKey> =
            match self.get_if_address_allowed(address, document_id) {
                None => None,
                Some(entry) => self
                    .documents
                    .iter()
                    .find(|item| item.id == document_id)
                    .map(|item| item.key.as_ref()),
            };
        retval
    }

    pub fn set_address_allowed(&mut self, address: u64, document_id: u64) {
        if self
            .permission_entries
            .iter()
            .find(|x| x.allowed_account == address)
            == None
        {
            self.permission_entries.push(PermissionEntry {
                allowed_account: address,
                document_id: vec![document_id],
            });
        }
        {
            self.permission_entries
                .iter_mut()
                .find(|x| x.allowed_account == address)
                .unwrap()
                .document_id
                .push(document_id);
        }
    }

    pub fn set_address_disallowed(&mut self, address: u64, document_id: u64) {
        if self
            .permission_entries
            .iter()
            .find(|x| x.allowed_account == address)
            != None
        {
            self.permission_entries
                .iter_mut()
                .find(|x| x.allowed_account == address)
                .unwrap()
                .document_id
                .retain(|x| x != &document_id);
        }
    }

    pub fn add_document_key_pair(&mut self, document_id: u64, document_key: EncryptedDocumentKey) {
        self.documents.push(Document {
            id: document_id,
            key: document_key,
        });
    }
}
