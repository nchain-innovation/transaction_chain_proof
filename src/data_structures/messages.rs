use chain_gang::messages::OutPoint;
use chain_gang::messages::Tx;

use ark_ff::ToBytes;
use chain_gang::util::Hash256;
use chain_gang::util::Serializable;
use std::io::Result as IoResult;
use std::io::Write;

use std::{borrow::Borrow, marker::PhantomData};

use ark_ff::PrimeField;

use bitcoin_r1cs::{
    constraints::{outpoint::OutPointVar, tx::TxVarConfig},
    sha256::constraints::DigestVar,
};

use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::{ToBytesGadget, alloc::AllocVar};

use ark_r1cs_std::uint8::UInt8;

/// Message being sent between parties in [TransactionChainProofPredicate]
#[derive(Clone)]
pub struct MessageOutPoint {
    /// The outpoint holding the token
    pub outpoint: OutPoint,
}

/// R1CS version of [MessageOutPoint]
pub struct MessageOutPointVar<F: PrimeField, P: TxVarConfig + Clone> {
    pub outpoint: OutPointVar<F>,
    _config: PhantomData<P>,
}

/// Message being sent between the parties in a [UniversalTransactionChainProofPredicate]
#[derive(Clone)]
pub struct MessageUniversalTCP {
    /// The outpoint holding the token
    pub outpoint: OutPoint,
    /// The txid from where the token originates
    pub genesis_txid: [u8; 32],
}

/// R1CS version of the message [MessageUniversalTCP]
pub struct MessageUniversalTCPVar<F: PrimeField> {
    pub outpoint: OutPointVar<F>,
    pub genesis_txid: DigestVar<F>,
}

// Implementation of MessageOutpoint
impl MessageOutPoint {
    pub fn new(outpoint: &OutPoint) -> Self {
        Self {
            outpoint: outpoint.clone(),
        }
    }

    pub fn from_tx(value: Tx, input_index: usize) -> Self {
        MessageOutPoint::new(&value.inputs[input_index].prev_output)
    }
}

impl ToBytes for MessageOutPoint {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.outpoint.write(&mut writer)
    }
}

impl From<OutPoint> for MessageOutPoint {
    fn from(value: OutPoint) -> Self {
        MessageOutPoint::new(&value)
    }
}

impl Default for MessageOutPoint {
    fn default() -> Self {
        Self::new(&OutPoint {
            hash: Hash256([0; 32]),
            index: 0,
        })
    }
}

// Implementation of MessageOutPointVar
impl<F: PrimeField, P: TxVarConfig + Clone> ToBytesGadget<F> for MessageOutPointVar<F, P> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.outpoint.to_bytes()
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> AllocVar<MessageOutPoint, F>
    for MessageOutPointVar<F, P>
{
    fn new_variable<T: Borrow<MessageOutPoint>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let msg_outpoint: MessageOutPoint =
            f().map(|msg_outpoint| msg_outpoint.borrow().clone())?;

        Ok(Self {
            outpoint: OutPointVar::<F>::new_variable(
                cs.clone(),
                || Ok(msg_outpoint.outpoint),
                mode,
            )?,
            _config: PhantomData,
        })
    }
}

// Implementation of MessageUniversalTCP
impl MessageUniversalTCP {
    pub fn new(outpoint: &OutPoint, genesis_txid: &[u8; 32]) -> Self {
        Self {
            outpoint: outpoint.clone(),
            genesis_txid: *genesis_txid,
        }
    }

    pub fn new_from_tx(tx: &Tx, input_index: u32, genesis_txid: &[u8; 32]) -> Self {
        Self::new(&tx.inputs[input_index as usize].prev_output, genesis_txid)
    }
}

impl ToBytes for MessageUniversalTCP {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.outpoint.write(&mut writer)?;
        Serializable::write(&self.genesis_txid, &mut writer)
    }
}

impl Default for MessageUniversalTCP {
    fn default() -> Self {
        Self::new(
            &OutPoint {
                hash: Hash256([0; 32]),
                index: 0,
            },
            &[0; 32],
        )
    }
}

// Implementation of MessageUniversalTCPVar
impl<F: PrimeField> MessageUniversalTCPVar<F> {
    pub fn new(outpoint: &OutPointVar<F>, genesis_txid: &DigestVar<F>) -> Self {
        Self {
            outpoint: outpoint.clone(),
            genesis_txid: genesis_txid.clone(),
        }
    }
}

impl<F: PrimeField> AllocVar<MessageUniversalTCP, F> for MessageUniversalTCPVar<F> {
    fn new_variable<T: Borrow<MessageUniversalTCP>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let msg: MessageUniversalTCP = f().map(|msg| msg.borrow().clone())?;

        let outpoint: OutPointVar<F> =
            OutPointVar::<F>::new_variable(cs.clone(), || Ok(msg.outpoint.clone()), mode)?;
        let mut genesis_txid: Vec<UInt8<F>> = Vec::with_capacity(32);
        for byte in msg.genesis_txid {
            genesis_txid.push(UInt8::<F>::new_variable(cs.clone(), || Ok(byte), mode)?);
        }

        Ok(MessageUniversalTCPVar::new(
            &outpoint,
            &DigestVar::<F>(genesis_txid),
        ))
    }
}

impl<F: PrimeField> ToBytesGadget<F> for MessageUniversalTCPVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let mut result: Vec<UInt8<F>> = Vec::with_capacity(68);
        result.extend_from_slice(self.outpoint.to_bytes()?.as_slice());
        result.extend_from_slice(self.genesis_txid.to_bytes()?.as_slice());

        Ok(result)
    }
}
