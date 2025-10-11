//! Core utilities and Sans-IO abstractions for superd.
//!
//! This crate provides common types and traits for implementing
//! network services using the Sans-IO methodology.

pub mod sans_io;

/// A basic Sans-IO event loop trait.
pub trait EventLoop {
    type Input;
    type Output;

    fn handle_input(&mut self, input: Self::Input) -> Vec<Self::Output>;
}