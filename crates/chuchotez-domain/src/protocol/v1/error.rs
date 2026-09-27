//! Library errors.

/// Failure from a named Engine method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineError {
    /// The conversation is in the wrong phase for this method.
    WrongPhase,
    /// Ticket host string failed parse.
    MalformedTicket,
    /// `expires` is less than or equal to the ticked now.
    ExpiresNotAfterNow,
    /// Unknown user, identity, or conversation id.
    UnknownIds,
    /// Display name failed its gate.
    MalformedDisplayName,
    /// Channel list length or uniqueness failed.
    ChannelBounds,
    /// Persist bytes failed unlock or parse.
    MalformedPersist,
    /// `poll` or a mint ran before the first successful `tick`.
    NotTicked,
    /// `tick` `now` is less than the last ticked now.
    ClockWentBackwards,
    /// Ingest or ack tag is unknown.
    UnknownTag,
    /// `writeAck` body is unknown.
    UnknownWrite,
    /// Packed packet exceeded 484 bytes or DurableBody exceeded 64 fragments.
    BodyTooLarge,
    /// Body, caption, emoji, filename, mime, or profile WebP failed its bounds.
    MalformedPayload,
    /// Vault unlock failed.
    UnlockFailed,
    /// The DEK is not held.
    Locked,
    /// Wake endpoint or key lengths failed.
    MalformedWake,
    /// `receiveSyncTicket` requires an empty EngineState.
    EmptyEngineRequired,
    /// Owner-only method on a Group.
    NotOwner,
    /// Group member cap or device cap.
    MemberCap,
    /// Duplicate group member.
    DuplicateMember,
    /// Same `tx_id` with a disagreeing payload.
    Equivocation,
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::WrongPhase => "wrong phase",
            Self::MalformedTicket => "malformed ticket",
            Self::ExpiresNotAfterNow => "expires not after now",
            Self::UnknownIds => "unknown ids",
            Self::MalformedDisplayName => "malformed display name",
            Self::ChannelBounds => "channel bounds",
            Self::MalformedPersist => "malformed persist",
            Self::NotTicked => "not ticked",
            Self::ClockWentBackwards => "clock went backwards",
            Self::UnknownTag => "unknown tag",
            Self::UnknownWrite => "unknown write",
            Self::BodyTooLarge => "body too large",
            Self::MalformedPayload => "malformed payload",
            Self::UnlockFailed => "unlock failed",
            Self::Locked => "locked",
            Self::MalformedWake => "malformed wake",
            Self::EmptyEngineRequired => "empty engine required",
            Self::NotOwner => "not owner",
            Self::MemberCap => "member cap",
            Self::DuplicateMember => "duplicate member",
            Self::Equivocation => "equivocation",
        };
        f.write_str(s)
    }
}

impl std::error::Error for EngineError {}

#[cfg(test)]
mod tests {
    use super::EngineError;

    #[test]
    fn engine_error_display() {
        for (e, s) in [
            (EngineError::WrongPhase, "wrong phase"),
            (EngineError::MalformedTicket, "malformed ticket"),
            (EngineError::ExpiresNotAfterNow, "expires not after now"),
            (EngineError::UnknownIds, "unknown ids"),
            (EngineError::MalformedDisplayName, "malformed display name"),
            (EngineError::ChannelBounds, "channel bounds"),
            (EngineError::MalformedPersist, "malformed persist"),
            (EngineError::NotTicked, "not ticked"),
            (EngineError::ClockWentBackwards, "clock went backwards"),
            (EngineError::UnknownTag, "unknown tag"),
            (EngineError::UnknownWrite, "unknown write"),
            (EngineError::BodyTooLarge, "body too large"),
            (EngineError::MalformedPayload, "malformed payload"),
            (EngineError::UnlockFailed, "unlock failed"),
            (EngineError::Locked, "locked"),
            (EngineError::MalformedWake, "malformed wake"),
            (EngineError::EmptyEngineRequired, "empty engine required"),
            (EngineError::NotOwner, "not owner"),
            (EngineError::MemberCap, "member cap"),
            (EngineError::DuplicateMember, "duplicate member"),
            (EngineError::Equivocation, "equivocation"),
        ] {
            assert_eq!(format!("{e}"), s);
            assert_eq!(e, e);
        }
        let _ = &EngineError::Locked as &dyn std::error::Error;
        assert_ne!(EngineError::Locked, EngineError::WrongPhase);
    }
}
