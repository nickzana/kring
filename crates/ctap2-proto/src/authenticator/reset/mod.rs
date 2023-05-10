/// Possible errors for the [`Ctap2Device::reset`] command.
pub enum Error {
    /// Returned if the `reset` operation is disabled for the transport used or
    /// if user precense is explicitly denied.
    OperationDenied,
    /// Returned when a user action timeout occurs.
    ///
    /// > This refers to a timeout that occurs when the authenticator is waiting
    /// > for direct action from the user, like a touch. (I.e. not a command
    /// > from the platform.) The duration of this timeout is chosen by the
    /// > authenticator but MUST be at least 10 seconds. Thirty seconds is a
    /// > reasonable value.
    UserActionTimeout,
    /// Returned when the `reset` request is received by the authenticator more
    /// than ten seconds after powering up.
    NotAllowed,
}
