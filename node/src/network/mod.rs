// M13 NODE — NETWORK MODULE
// Datapath (TUN device, routing, cleanup).
// uring_reactor: io_uring SQPOLL + PBR zero-syscall reactor.
// uso_pacer: Userspace Segmentation Offload (USO) MTU slicing.

pub mod datapath;
pub mod uring_reactor;
pub mod uso_pacer;