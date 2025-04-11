# Prompt for Rewriting tss-lib-go to tss-lib-rust

**Goal:** Rewrite the Go library located in the `tss-lib-go` directory into an equivalent Rust library in the `tss-lib-rust` directory.

**Source Directory:** `./tss-lib-go`
**Target Directory:** `./tss-lib-rust`

**Key Constraints & Requirements:**

1.  **Maintain Directory Structure:** Replicate the directory and file structure from `tss-lib-go` within `tss-lib-rust`. For each `.go` file, create a corresponding `.rs` file (or `mod.rs` as appropriate for Rust modules) in the same relative path.
2.  **Idiomatic Rust:** Translate Go code, concepts, and patterns into safe, performant, and idiomatic Rust. Pay attention to error handling (Result/panic), memory management (ownership, borrowing), concurrency (async/await, threads), and data structures.
3.  **Functional Equivalence:** The resulting Rust library must provide the same core functionality and APIs as the original Go library. Public interfaces should be preserved where possible, adapting to Rust conventions.
4.  **Minimal Dependencies:** Do NOT introduce external Rust crates unless absolutely necessary and clearly justified. Prioritize using the Rust standard library. If a crate is needed, explain why the standard library is insufficient.
5.  **Self-Sufficiency & Role-Play:** You must handle the entire process autonomously. If you encounter ambiguity in the Go code or face a choice in Rust implementation (e.g., "How should this Go interface be represented in Rust?", "What's the idiomatic Rust way to handle this error pattern?", "Is this global state necessary or can it be refactored?"), follow these steps:
    *   Clearly state the question or ambiguity you've identified.
    *   Immediately provide a reasoned answer or decision, justifying it based on Rust best practices and the inferred intent of the Go code. Act as both the question-asker (analyzing Go) and the expert Rust developer (providing the solution).
    *   Proceed with the implementation based on your reasoned answer.
6.  **Process:** Work through the Go codebase systematically, **one file or module at a time**. Start with the root directory or a logical entry point. After processing one file/module, clearly state which one you completed and which one you intend to process next. **Wait for a "continue" instruction before proceeding to the next file/module.**

**Output:** For the **current** file/module being processed, generate the corresponding Rust code in the `tss-lib-rust` directory. Ensure the generated code is complete and ready for compilation (including necessary `use` statements, module declarations, etc.). State the full path of the Rust file you just generated and the full path of the Go file you will process next. 