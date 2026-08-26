// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

//! The engine has two layers: [`tokenizer`] turns message bytes into tokens,
//! then [`scoring`] combines tokens and fetched counts into a decision while
//! its pure [`scoring::centre_from_base_rate`] helper exposes a default-off
//! empirical prior. [`storage`] provides the SQLite schema plus caller-owned
//! transaction operations for training, untraining, and correction. The default `cli`
//! feature adds environment and configuration-file readers used by the
//! binaries. Without `cli`, the engine performs no environment or
//! configuration-file reads; its only filesystem access is the SQLite
//! database itself and its parent directory.

pub mod scoring;
pub mod storage;
pub mod tokenizer;

pub use scoring as classifier;
