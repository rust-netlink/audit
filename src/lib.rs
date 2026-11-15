// SPDX-License-Identifier: MIT

mod codec;
pub use crate::codec::NetlinkAuditCodec;

mod handle;
pub use crate::handle::*;

mod errors;
pub use crate::errors::*;

pub use netlink_packet_audit as packet;
use netlink_packet_core::NetlinkMessage;
pub mod proto {
    pub use netlink_proto::{
        Connection, ConnectionHandle, NetlinkProtoError as Error,
    };
}
pub use netlink_proto::sys;

use futures::channel::mpsc::UnboundedReceiver;

#[allow(clippy::type_complexity)]
#[cfg(feature = "tokio_socket")]
pub fn new_connection() -> Result<
    (
        proto::Connection<
            packet::AuditMessage,
            sys::TokioSocket,
            NetlinkAuditCodec,
        >,
        Handle,
        UnboundedReceiver<(
            NetlinkMessage<packet::AuditMessage>,
            sys::SocketAddr,
        )>,
    ),
    proto::Error,
> {
    new_connection_with_socket()
}

#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> Result<
    (
        proto::Connection<packet::AuditMessage, S, NetlinkAuditCodec>,
        Handle,
        UnboundedReceiver<(
            NetlinkMessage<packet::AuditMessage>,
            sys::SocketAddr,
        )>,
    ),
    proto::Error,
>
where
    S: sys::AsyncSocket,
{
    let (conn, handle, messages) =
        netlink_proto::new_connection_with_codec(libc::NETLINK_AUDIT as isize)?;
    Ok((conn, Handle::new(handle), messages))
}
