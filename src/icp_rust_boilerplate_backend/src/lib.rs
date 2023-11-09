#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::{api::time, IDL};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct SecretMessage {
    id: u64,
    encrypted_message: String,
    created_at: u64,
    updated_at: Option<u64>,
    secret_key: String,
}

impl Storable for SecretMessage {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for SecretMessage {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static STORAGE: RefCell<StableBTreeMap<u64, SecretMessage, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));
}

#[derive(candid::CandidType, Serialize, Deserialize, Default)]
struct SecretMessagePayload {
    encrypted_message: String,
    secret_key: String,
}

#[derive(Debug, PartialEq, Eq)]
struct User {
    roles: Vec<String>,
}

#[ic_cdk::query]
fn get_message(id: u64, secret_key: String, user: User) -> Result<String, Error> {
    // Access control: Check if the user has the necessary role
    if !user.roles.contains(&"admin".to_string()) {
        return Err(Error::Unauthorized {
            msg: "Unauthorized: Insufficient privileges.".to_string(),
        });
    }

    let message = _get_message(&id).ok_or_else(|| Error::NotFound {
        msg: format!("A message with id={} not found", id),
    })?;

    // Validate user's access to the specific message
    if message.secret_key == secret_key {
        Ok(message.encrypted_message)
    } else {
        Err(Error::Unauthorized {
            msg: "Unauthorized: Invalid secret key.".to_string(),
        })
    }
}

#[ic_cdk::update]
fn add_message(message: SecretMessagePayload, user: User) -> Result<SecretMessage, Error> {
    // Access control: Check if the user has the necessary role
    if !user.roles.contains(&"admin".to_string()) {
        return Err(Error::Unauthorized {
            msg: "Unauthorized: Insufficient privileges.".to_string(),
        });
    }

    // Validate input
    if message.encrypted_message.is_empty() || message.secret_key.is_empty() {
        return Err(Error::InvalidInput {
            msg: "Both encrypted_message and secret_key must be non-empty".to_string(),
        });
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .map_err(|_| Error::CounterIncrementFailed)?;

    let secret_message = SecretMessage {
        id,
        encrypted_message: message.encrypted_message,
        created_at: time(),
        updated_at: None,
        secret_key: message.secret_key,
    };

    do_insert(&secret_message);
    Ok(secret_message)
}

// Helper method to perform insert.
fn do_insert(message: &SecretMessage) {
    STORAGE.with(|service| service.borrow_mut().insert(message.id, message.clone()));
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    Unauthorized { msg: String },
    InvalidInput { msg: String },
    CounterIncrementFailed,
}

// A helper method to get a message by id. Used in get_message.
fn _get_message(id: &u64) -> Option<SecretMessage> {
    STORAGE.with(|service| service.borrow().get(id))
}

// Export the Candid interface.
ic_cdk::export_candid!();
