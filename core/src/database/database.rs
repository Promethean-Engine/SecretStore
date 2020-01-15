use crate::types::EncryptedDocumentKey;
use parity_crypto::publickey::{Public, Secret};

#[derive(Default, Debug, PartialEq)]
pub struct PermissionDatabase {
    permission_entries: Vec<PermissionEntry>,
    documents: Vec<Document>,
    server_key_shares: Vec<ServerKey>,
}

#[derive(Debug, PartialEq)]
pub struct ServerKey {
    public_key: Public,
    secret_key_share: Secret,
    bound_document_id: u64,
}

#[derive(Default, Debug, PartialEq, Clone)]
struct PermissionEntry {
    pub allowed_account: u64,
    pub document_id: Vec<u64>,
}

#[derive(Default, Debug, PartialEq, Clone)]
struct Document {
    pub id: u64,
    pub secret_key: EncryptedDocumentKey,
    pub public_key: Public,
}

impl PermissionDatabase {
    pub fn new() -> Self {
        PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
            server_key_shares: Vec::new(),
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
                    .map(|item| item.secret_key.as_ref()),
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

    pub fn add_document_key_pair(
        &mut self,
        document_id: u64,
        document_key: EncryptedDocumentKey,
        public_key: Public,
    ) {
        self.documents.push(Document {
            id: document_id,
            secret_key: document_key,
            public_key: public_key,
        });
    }

    pub fn add_server_key_by_document(
        &mut self,
        document_id: u64,
        server_public_key: Public,
        server_private_key_share: Secret,
    ) {
        self.server_key_shares.push(ServerKey {
            public_key: server_public_key,
            secret_key_share: server_private_key_share,
            bound_document_id: document_id,
        });
    }

    pub fn get_server_key_by_document(&self, document_id: u64) -> Option<&ServerKey> {
        self.server_key_shares
            .iter()
            .find(|x| x.bound_document_id == document_id)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use parity_crypto::publickey::{Generator, Random};

    #[test]
    fn test_add_document_key_pair() {
        let mut database = PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
            server_key_shares: Vec::new(),
        };
        database.add_document_key_pair(
            0,
            bytes::Bytes::new(),
            Random.generate().unwrap().public().clone(),
        );
    }

    #[test]
    fn test_set_address_allowed() {
        let mut database = PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
            server_key_shares: Vec::new(),
        };
        database.add_document_key_pair(
            0,
            bytes::Bytes::new(),
            Random.generate().unwrap().public().clone(),
        );
        database.set_address_allowed(0, 0)
    }

    #[test]
    fn test_set_existing_address_disallowed() {
        let mut database = PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
            server_key_shares: Vec::new(),
        };
        database.add_document_key_pair(
            0,
            bytes::Bytes::new(),
            Random.generate().unwrap().public().clone(),
        );
        database.set_address_allowed(0, 0);
        database.set_address_disallowed(0, 0);
    }

    #[test]
    fn test_set_non_existing_address_disallowed() {
        let mut database = PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
            server_key_shares: Vec::new(),
        };
        database.add_document_key_pair(
            0,
            bytes::Bytes::new(),
            Random.generate().unwrap().public().clone(),
        );
        database.set_address_disallowed(0, 0);
    }

    #[test]
    fn test_get_if_address_allowed() {
        let mut database = PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
            server_key_shares: Vec::new(),
        };
        database.add_document_key_pair(
            0,
            bytes::Bytes::new(),
            Random.generate().unwrap().public().clone(),
        );
        database.set_address_allowed(0, 0);
        assert!(database.get_if_address_allowed(0, 0).is_some());
    }

    #[test]
    fn test_get_encrypted_document_key() {
        let mut database = PermissionDatabase {
            permission_entries: Vec::new(),
            documents: Vec::new(),
            server_key_shares: Vec::new(),
        };
        database.add_document_key_pair(
            0,
            bytes::Bytes::new(),
            Random.generate().unwrap().public().clone(),
        );
        database.set_address_allowed(0, 0);
        assert!(database.get_encrypted_document_key(0, 0).is_some());
    }
}
