// SPDX-License-Identifier: MIT

//! In this example, we create two rules which is equivalent to the following
//! commands:
//!
//! auditctl -w /etc/passwd -p rwxa -k my_key
//! auditctl -a always,exit -F arch=b64 -S personality -F key=bypass

use audit::{
    new_connection,
    packet::{
        constants::AUDIT_ARCH_X86_64, RuleAction, RuleField, RuleFieldFlags,
        RuleFlags, RuleMessage, RuleSyscalls,
    },
    Error, Handle,
};

#[tokio::main]
async fn main() -> Result<(), String> {
    let (connection, handle, _) =
        new_connection().map_err(|e| format!("{e}"))?;
    tokio::spawn(connection);
    add_rules(handle).await.map_err(|e| format!("{e}"))
}

async fn add_rules(mut handle: Handle) -> Result<(), Error> {
    let mut etc_passwd_rule = RuleMessage::default();
    etc_passwd_rule.flags = RuleFlags::FilterExit;
    etc_passwd_rule.action = RuleAction::Always;
    etc_passwd_rule.fields = vec![
        (
            RuleField::Watch("/etc/passwd".into()),
            RuleFieldFlags::Equal,
        ),
        (RuleField::Perm(15), RuleFieldFlags::Equal),
        (RuleField::Filterkey("my_key".into()), RuleFieldFlags::Equal),
    ];
    etc_passwd_rule.syscalls = RuleSyscalls::new_maxed();
    handle.add_rule(etc_passwd_rule).await?;

    let mut syscalls = RuleSyscalls::new_zeroed();
    syscalls.set(135);
    let mut personality_syscall_rule = RuleMessage::default();
    personality_syscall_rule.flags = RuleFlags::FilterExit;
    personality_syscall_rule.action = RuleAction::Always;
    personality_syscall_rule.fields = vec![
        (RuleField::Arch(AUDIT_ARCH_X86_64), RuleFieldFlags::Equal),
        (RuleField::Filterkey("bypass".into()), RuleFieldFlags::Equal),
    ];
    personality_syscall_rule.syscalls = syscalls;

    handle.add_rule(personality_syscall_rule).await?;
    Ok(())
}
