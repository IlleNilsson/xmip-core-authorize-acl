#![forbid(unsafe_code)]

//! The acl authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: an access-control list per artifact
//! (ADR-0050 section 5). An [`Entry`] is a [`Subject`] — a Party, an identity
//! by the value the gate recorded, or anyone — an action or any, a target
//! pattern over artifact names, and allow or deny. The entries are consulted
//! in order and the first that matches decides, with one exception: two
//! entries that name the same subject, the same action and the same target
//! and disagree are a tie, and a tie is a denial. A contradiction written
//! into an access list is not a permission.
//!
//! The identity judged is the accountable one, the transport identity, as
//! ADR-0019 clause 7 has it. An attempt no entry matches is no opinion.

use authorize::{Action, Attempt, Authorizer, Decision};
use context::{AuthenticatedIdentity, IdentityFacts};
use std::fmt;
use xcore::{Layer, PartyId};

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "acl";

/// Who an entry is about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Subject {
    /// The identity resolved to this Party.
    Party(PartyId),
    /// The gate recorded this value, under any mechanism.
    Identity(String),
    /// Every identity the gates authenticated, anonymous included.
    Anyone,
}

impl Subject {
    fn matches(&self, identity: &AuthenticatedIdentity) -> bool {
        match self {
            Self::Party(party) => identity.party_id == Some(*party),
            Self::Identity(value) => *value == identity.value,
            Self::Anyone => true,
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Party(party) => write!(f, "Party {party}"),
            Self::Identity(value) => f.write_str(value),
            Self::Anyone => f.write_str("anyone"),
        }
    }
}

/// What an entry concludes where it matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Allow,
    Deny,
}

/// One line of the list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    subject: Subject,
    action: Option<Action>,
    target: String,
    access: Access,
}

impl Entry {
    /// Allow a subject an action — or any, as `None` — on artifacts matching
    /// the target pattern.
    #[must_use]
    pub fn allow(subject: Subject, action: Option<Action>, target: impl Into<String>) -> Self {
        Self::new(subject, action, target, Access::Allow)
    }

    /// Deny a subject an action — or any, as `None` — on artifacts matching
    /// the target pattern.
    #[must_use]
    pub fn deny(subject: Subject, action: Option<Action>, target: impl Into<String>) -> Self {
        Self::new(subject, action, target, Access::Deny)
    }

    fn new(
        subject: Subject,
        action: Option<Action>,
        target: impl Into<String>,
        access: Access,
    ) -> Self {
        Self {
            subject,
            action,
            target: target.into(),
            access,
        }
    }

    fn matches(&self, identity: &AuthenticatedIdentity, attempt: &Attempt) -> bool {
        self.subject.matches(identity)
            && self.action.is_none_or(|action| action == attempt.action)
            && matches(&self.target, &attempt.artifact)
    }

    /// The same subject, action and target: a tie where the access differs.
    fn ties_with(&self, other: &Self) -> bool {
        self.subject == other.subject && self.action == other.action && self.target == other.target
    }
}

/// The list, in the order it is consulted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Acl {
    entries: Vec<Entry>,
}

impl Acl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry after those already there.
    #[must_use]
    pub fn entry(mut self, entry: Entry) -> Self {
        self.entries.push(entry);
        self
    }
}

impl Authorizer for Acl {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let accountable = identity.accountable();
        let mut matching = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.matches(accountable, attempt));
        let (position, first) = matching.next()?;

        let denial = |position: usize, entry: &Entry, why: &str| {
            Decision::denied(
                NAME,
                format!(
                    "entry {position} {why}: {} may not {} on '{}'",
                    entry.subject, attempt.action, attempt.artifact
                ),
            )
        };

        if first.access == Access::Deny {
            return Some(denial(position, first, "denies"));
        }

        // First match wins, unless a later entry contradicts it line for
        // line: the list then says both, and deny beats allow on a tie.
        match matching.find(|(_, entry)| entry.access == Access::Deny && entry.ties_with(first)) {
            Some((contradicting, entry)) => Some(denial(
                contradicting,
                entry,
                &format!("contradicts entry {position}, and deny beats allow on a tie"),
            )),
            None => Some(Decision::Allowed),
        }
    }
}

/// Whether a name matches a pattern, where `*` stands for any run of
/// characters and everything else stands for itself.
#[must_use]
pub fn matches(pattern: &str, name: &str) -> bool {
    let mut pieces = pattern.split('*');
    let Some(head) = pieces.next() else {
        return name.is_empty();
    };
    let Some(mut rest) = name.strip_prefix(head) else {
        return false;
    };
    let mut pieces = pieces.peekable();

    while let Some(piece) = pieces.next() {
        let last = pieces.peek().is_none();
        if last {
            return rest.ends_with(piece);
        }
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }

    rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::{Alignment, Verified};
    use xcore::{Established, mechanism};

    fn tls(party: Option<PartyId>) -> IdentityFacts {
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
            Established::Passed,
            Verified::Proven,
        );
        let identity = match party {
            Some(party) => identity.resolving_to(party),
            None => identity,
        };

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn acl() -> Acl {
        Acl::new()
            .entry(Entry::deny(Subject::Anyone, Some(Action::Send), "Billing*"))
            .entry(Entry::allow(
                Subject::Party(PartyId::new(1)),
                Some(Action::Receive),
                "partner-*",
            ))
            .entry(Entry::allow(
                Subject::Identity("CN=partner-x.example".into()),
                None,
                "Shipping",
            ))
    }

    #[test]
    fn the_first_entry_that_matches_allows() {
        let decision = acl().decide(
            &tls(Some(PartyId::new(1))),
            &Attempt::new(Action::Receive, "partner-x"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(acl().name(), "acl");
        assert_eq!(acl().layer(), Layer::Transport);
    }

    #[test]
    fn the_first_entry_that_matches_denies_naming_its_position() {
        let decision = acl()
            .decide(
                &tls(Some(PartyId::new(1))),
                &Attempt::new(Action::Send, "Billing"),
            )
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by acl: entry 0 denies: anyone may not send on 'Billing'"
        );
    }

    #[test]
    fn an_attempt_no_entry_matches_is_no_opinion() {
        assert_eq!(
            acl().decide(
                &tls(Some(PartyId::new(2))),
                &Attempt::new(Action::Receive, "partner-x")
            ),
            None
        );
        assert_eq!(
            acl().decide(&tls(None), &Attempt::new(Action::Process, "Approval")),
            None
        );
    }

    #[test]
    fn a_contradicting_pair_is_a_tie_and_deny_beats_allow() {
        // Line for line the same subject, action and target, once allowed and
        // once denied. An earlier deny wins by order; a later one wins by the
        // tie rule; a later deny on a different target is not a tie.
        let tie = Acl::new()
            .entry(Entry::allow(Subject::Anyone, None, "Shipping"))
            .entry(Entry::deny(Subject::Anyone, None, "Shipping"));
        let decision = tie
            .decide(&tls(None), &Attempt::new(Action::Send, "Shipping"))
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by acl: entry 1 contradicts entry 0, and deny beats allow on a tie: \
             anyone may not send on 'Shipping'"
        );

        let no_tie = Acl::new()
            .entry(Entry::allow(Subject::Anyone, None, "Shipping"))
            .entry(Entry::deny(Subject::Anyone, None, "Ship*"));

        assert_eq!(
            no_tie.decide(&tls(None), &Attempt::new(Action::Send, "Shipping")),
            Some(Decision::Allowed),
            "first match wins where the lines differ"
        );
    }

    #[test]
    fn an_identity_entry_matches_the_recorded_value_under_any_action() {
        assert_eq!(
            acl().decide(&tls(None), &Attempt::new(Action::Process, "Shipping")),
            Some(Decision::Allowed)
        );
        assert!(matches("Billing*", "Billing"));
        assert!(matches("partner-*", "partner-x"));
        assert!(!matches("partner-*", "Partner-x"));
    }
}
