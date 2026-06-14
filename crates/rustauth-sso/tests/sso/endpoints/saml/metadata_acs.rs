use super::*;

#[path = "metadata_acs/default_sso.rs"]
mod default_sso;
#[path = "metadata_acs/flows.rs"]
mod flows;
#[path = "metadata_acs/idp_initiated.rs"]
mod idp_initiated;
#[path = "metadata_acs/linking.rs"]
mod linking;
#[path = "metadata_acs/metadata.rs"]
mod metadata;
#[path = "metadata_acs/provisioning.rs"]
mod provisioning;
#[path = "metadata_acs/signed.rs"]
mod signed;
#[path = "metadata_acs/slo_session.rs"]
mod slo_session;
#[path = "metadata_acs/state.rs"]
mod state;
#[path = "metadata_acs/validation.rs"]
mod validation;
