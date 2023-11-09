#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct ReferralReward {
    id: u64,
    title: String,
    body: String,
    attachment_url: String,
    created_at: u64,
    updated_at: Option<u64>,
    user_name: String,          // New field: User's name
    referral_code: String,      // New field: Referral code
    reward_points: u32,         // New field: Reward points
}

impl Storable for ReferralReward {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for ReferralReward {
    const MAX_SIZE: u32 = 1024;  // You may need to adjust this value based on the new fields.
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

    static STORAGE: RefCell<StableBTreeMap<u64, ReferralReward, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));
}

#[derive(candid::CandidType, Serialize, Deserialize, Default)]
struct ReferralRewardPayload {
    title: String,
    body: String,
    attachment_url: String,
}

#[ic_cdk::query]
fn get_referral_reward(id: u64) -> Result<ReferralReward, Error> {
    match _get_referral_reward(&id) {
        Some(referral_reward) => Ok(referral_reward),
        None => Err(Error::NotFound {
            msg: format!("Referral reward with id={} not found", id),
        }),
    }
}

#[ic_cdk::update]
fn add_referral_reward(referral_reward: ReferralRewardPayload) -> Option<ReferralReward> {
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("cannot increment id counter");
    let referral_reward = ReferralReward {
        id,
        title: referral_reward.title,
        body: referral_reward.body,
        attachment_url: referral_reward.attachment_url,
        created_at: time(),
        updated_at: None,
        user_name: "John Doe".to_string(),  // Set the user's name
        referral_code: "ABC123".to_string(), // Set the referral code
        reward_points: 0,                  // Initialize reward points
    };
    do_insert(&referral_reward);
    Some(referral_reward)
}

// Other functions remain unchanged

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
}

fn do_insert(referral_reward: &ReferralReward) {
    STORAGE.with(|service| service.borrow_mut().insert(referral_reward.id, referral_reward.clone()));
}

fn _get_referral_reward(id: &u64) -> Option<ReferralReward> {
    STORAGE.with(|service| service.borrow().get(id))
}

ic_cdk::export_candid!();
