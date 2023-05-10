use crate::credential::Credential;

#[derive(Clone, Copy)]
// TODO: Add actual link for `get`
/// > When making a request via `get(options)`, developers can set a
/// > case-by-case requirement for user mediation by choosing the
/// > appropriate [`Requirement`] enum value.
/// >
/// > <https://w3c.github.io/webappsec-credential-management/#mediation-requirements/>
pub enum Requirement {
    /// > User mediation is suppressed for the given operation. If the
    /// > operation can be performed without user involvement, wonderful. If
    /// > user involvement is necessary, then the operation will return null
    /// > rather than involving the user.
    Silent,
    /// > If credentials can be handed over for a given operation without
    /// > user mediation, they will be. If user mediation is required, then
    /// > the user agent will involve the user in the decision.
    Optional,
    /// > Discovered credentials are presented to the user in a non-modal
    /// > dialog along with an indication of the origin which is requesting
    /// > credentials.
    Conditional,
    /// > The user agent will not hand over credentials without user
    /// > mediation, even if the prevent silent access flag is unset for an
    /// > origin.
    Required,
}

/// Conformance to this trait indicates the Credential "...supports the
/// conditional approach to mediation of credential requests for the
/// credential type". This eliminates the need for the
/// `isConditionalMediationAvailable` function specified in the specs.
///
/// <https://w3c.github.io/webappsec-credential-management/#dom-credentialmediationrequirement-conditional/>
pub trait Conditional: Credential {}
