use std::{borrow::Borrow, marker::PhantomData};

use ark_ff::PrimeField;
use chain_gang::messages::Tx;

use bitcoin_r1cs::constraints::tx::{TxVar, TxVarConfig};
use bitcoin_r1cs::util::default_tx;

use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::alloc::AllocVar;

use ark_r1cs_std::prelude::AllocationMode;

/// Local witness in [TransactionChainProofPredicate] and [UniversalTransactionChainProofPredicate]
#[derive(Clone)]
pub struct LocalWitnessOutPoint<P: TxVarConfig + Clone> {
    /// The transaction s.t. OutPoint := (tx.txid(), chain_index) holds the token
    pub tx: Tx,
    _config: PhantomData<P>,
}

// Implementation of LocalWitnessOutPoint
impl<P: TxVarConfig + Clone> LocalWitnessOutPoint<P> {
    pub fn new(tx: &Tx) -> Self {
        Self {
            tx: tx.clone(),
            _config: PhantomData,
        }
    }
}

impl<P: TxVarConfig + Clone> From<Tx> for LocalWitnessOutPoint<P> {
    fn from(value: Tx) -> Self {
        LocalWitnessOutPoint::new(&value)
    }
}

impl<P: TxVarConfig + Clone> Default for LocalWitnessOutPoint<P> {
    fn default() -> Self {
        Self::new(&default_tx::<P>())
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> AllocVar<LocalWitnessOutPoint<P>, F> for TxVar<F, P> {
    fn new_variable<T: Borrow<LocalWitnessOutPoint<P>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let witness: LocalWitnessOutPoint<P> = f().map(|witness| witness.borrow().clone())?;

        TxVar::<F, P>::new_variable(cs.clone(), || Ok(witness.tx), mode)
    }
}
