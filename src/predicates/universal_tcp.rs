use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_pcd::PCDPredicate;

use bitcoin_r1cs::constraints::{
    hash256::Hash256Gadget,
    outpoint::OutPointVar,
    tx::{TxVar, TxVarConfig},
};

use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use ark_r1cs_std::{ToBytesGadget, boolean::Boolean, uint32::UInt32};

use ark_r1cs_std::eq::EqGadget;

use crate::data_structures::{
    messages::{MessageUniversalTCP, MessageUniversalTCPVar},
    witnesses::LocalWitnessOutPoint,
};

/// The PCD predicate for a Universal Transaction Chain Proof.
///
/// The situation is the following:
///
/// **Parties:** Alice, Bob
///
/// **Common knowledge:** `genesis_txid`, `input_index`, `output_index`
///
/// **Goal:**
/// Alice holds a transaction `Tx` and she wants to prove that `Tx.outputs[output_index]` belongs to a transaction chain
/// with indices `(input_index, output_index)` starting at `genesis_txid`. Namely, there exist a chain `(Tx0, Tx1, Tx2, .., Txn)` such that:
/// 1. `Tx0.txid() = genesis_txid`
/// 2. `Tx(i+1).inputs[input_index] = (Txi.txid(), output_index)`, `0 <= i <= n-1`
/// 3. `Txn = Tx`
///
/// The circuit is the following:
/// - msg (a [MessageUniversalTCPVar])
/// - witness (a [LocalWitnessOutPoint])
/// - prior_msgs (a couple [MessageUniversalTCPVar])
///
///
/// ```"no_rust"
/// match base_case {
///     true => (msg.outpoint = (msg.genesis_txid, output_index))
///     false => {
///                (msg.outpoint = (witness.txid(), output_index))
///                     AND (msg.genesis_txid = prior_msgs.genesis_txid)
///                         AND (witness.inputs[input_index].prev_output = prior_msg.outpoint)
///     }
/// }
/// ```
///
/// **Note**: This predicate should only be used in a protocol in which Bob verifies that the public input contains the `genesis_txid`
/// he is interested in.
pub struct UniversalTransactionChainProofPredicate<P: TxVarConfig + Clone> {
    /// The indices of the chain
    pub input_index: u32,
    pub output_index: u32,
    /// The structure of the transactions in the chain
    _config: PhantomData<P>,
}

impl<P: TxVarConfig + Clone> UniversalTransactionChainProofPredicate<P> {
    pub fn new(input_index: u32, output_index: u32) -> Self {
        Self {
            input_index,
            output_index,
            _config: PhantomData,
        }
    }
}

impl<P: TxVarConfig + Clone> Clone for UniversalTransactionChainProofPredicate<P> {
    fn clone(&self) -> Self {
        Self {
            input_index: self.input_index,
            output_index: self.output_index,
            _config: PhantomData,
        }
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> PCDPredicate<F>
    for UniversalTransactionChainProofPredicate<P>
{
    type Message = MessageUniversalTCP;
    type MessageVar = MessageUniversalTCPVar<F>;

    type LocalWitness = LocalWitnessOutPoint<P>;
    type LocalWitnessVar = TxVar<F, P>;

    const PRIOR_MSG_LEN: usize = 1;

    fn generate_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        msg: &Self::MessageVar,
        witness: &Self::LocalWitnessVar,
        prior_msgs: &[Self::MessageVar],
        base_case: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let txid_witness = Hash256Gadget::<F>::evaluate(&witness.to_bytes()?)?;

        let base_case_expected_input = {
            OutPointVar::<F> {
                prev_tx: msg.genesis_txid.clone(),
                prev_index: UInt32::<F>::constant(self.output_index),
            }
        };

        let recursive_case_expected_input = {
            OutPointVar::<F> {
                prev_tx: txid_witness.clone(),
                prev_index: UInt32::<F>::constant(self.output_index),
            }
        };

        let is_base_case_verified = Boolean::<F>::kary_and(&[
            msg.outpoint.is_eq(&base_case_expected_input)?,
            base_case.clone(),
        ])?;
        let is_recursive_case_verified = Boolean::<F>::kary_and(&[
            msg.outpoint.is_eq(&recursive_case_expected_input)?,
            prior_msgs[0]
                .outpoint
                .is_eq(&witness.inputs[self.input_index as usize].prev_output)?,
            msg.genesis_txid.is_eq(&prior_msgs[0].genesis_txid)?,
        ])?;

        Boolean::<F>::kary_or(&[is_base_case_verified, is_recursive_case_verified])?
            .enforce_equal(&Boolean::<F>::TRUE)
    }
}

#[cfg(test)]
mod tests {

    use ark_pcd::PCDPredicate;
    use ark_r1cs_std::{alloc::AllocVar, prelude::Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use bitcoin_r1cs::constraints::tx::{TxVar, TxVarConfig};

    use ark_mnt4_298::Fq as ScalarFieldMNT6;
    use chain_gang::{
        messages::{OutPoint, Tx, TxIn},
        util::Serializable,
    };

    use crate::data_structures::messages::{MessageUniversalTCP, MessageUniversalTCPVar};

    use super::UniversalTransactionChainProofPredicate;

    use std::io::Cursor;

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 2;
        const N_OUTPUTS: usize = 2;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0x49, 0x49];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x23, 0x23];
        const LEN_PREV_LOCK_SCRIPT: Option<usize> = Some(0x23);
        const PRE_SIGHASH_N_INPUT: Option<usize> = None;
    }

    type TestTCP = UniversalTransactionChainProofPredicate<Config>;

    // Test transactions, they form a primary chain (chain_index = 0)
    fn transactions() -> [Tx; 3] {
        [
            Tx::read(
             &mut Cursor::new(hex::decode("010000000279730d2a2a09636ba3263c7bf4558e8fac852d4fcd7819a5b1cac2f2639b686e00000000494830450221009eda6ae95d014b177f923e7880ca9b95dbe95f7a190eee2c4a223752e1c84fb102200c727fdcd19cbb1f1fad49607b28971925c029f894003cffaf4024f6e13817d8010000000079730d2a2a09636ba3263c7bf4558e8fac852d4fcd7819a5b1cac2f2639b686e00000000494830450221009eda6ae95d014b177f923e7880ca9b95dbe95f7a190eee2c4a223752e1c84fb102200c727fdcd19cbb1f1fad49607b28971925c029f894003cffaf4024f6e13817d801000000000200000000000000002321028fede8b103cfece5c45d721c3db8fb238394e4094c0bb219cce296fcf99f51f6ac00000000000000002321028fede8b103cfece5c45d721c3db8fb238394e4094c0bb219cce296fcf99f51f6ac00000000").unwrap())
            ).unwrap(),
            Tx::read(
            &mut Cursor::new(hex::decode("01000000029ac1fdd730cc4697c9236358ef966d67e282747a32ae3244ed8b74d439b3a02200000000494830450221009eda6ae95d014b177f923e7880ca9b95dbe95f7a190eee2c4a223752e1c84fb102200c727fdcd19cbb1f1fad49607b28971925c029f894003cffaf4024f6e13817d8010000000079730d2a2a09636ba3263c7bf4558e8fac852d4fcd7819a5b1cac2f2639b686e01000000494830450221009eda6ae95d014b177f923e7880ca9b95dbe95f7a190eee2c4a223752e1c84fb102200c727fdcd19cbb1f1fad49607b28971925c029f894003cffaf4024f6e13817d801000000000200000000000000002321028fede8b103cfece5c45d721c3db8fb238394e4094c0bb219cce296fcf99f51f6ac00000000000000002321028fede8b103cfece5c45d721c3db8fb238394e4094c0bb219cce296fcf99f51f6ac00000000").unwrap())
            ).unwrap(),
            Tx::read(
            &mut Cursor::new(hex::decode("0100000002068c6e5d11052fec4abd5f1fb2775b6da8908197f87cb98e638ea8126899780400000000494830450221009eda6ae95d014b177f923e7880ca9b95dbe95f7a190eee2c4a223752e1c84fb102200c727fdcd19cbb1f1fad49607b28971925c029f894003cffaf4024f6e13817d8010000000079730d2a2a09636ba3263c7bf4558e8fac852d4fcd7819a5b1cac2f2639b686e01000000494830450221009eda6ae95d014b177f923e7880ca9b95dbe95f7a190eee2c4a223752e1c84fb102200c727fdcd19cbb1f1fad49607b28971925c029f894003cffaf4024f6e13817d801000000000200000000000000002321028fede8b103cfece5c45d721c3db8fb238394e4094c0bb219cce296fcf99f51f6ac00000000000000002321028fede8b103cfece5c45d721c3db8fb238394e4094c0bb219cce296fcf99f51f6ac00000000").unwrap())
            ).unwrap()
        ]
    }

    fn test_predicate(
        input_index: u32,
        output_index: u32,
        msg: <TestTCP as PCDPredicate<ScalarFieldMNT6>>::Message,
        prior_msg: <TestTCP as PCDPredicate<ScalarFieldMNT6>>::Message,
        witness: <TestTCP as PCDPredicate<ScalarFieldMNT6>>::LocalWitness,
        base_case: bool,
        expected_result: bool,
    ) -> () {
        let tcp = TestTCP::new(input_index, output_index);

        let cs = ConstraintSystem::<ScalarFieldMNT6>::new_ref();
        let msg_var =
            MessageUniversalTCPVar::<ScalarFieldMNT6>::new_input(cs.clone(), || Ok(msg)).unwrap();
        let prior_msg_var =
            MessageUniversalTCPVar::<ScalarFieldMNT6>::new_witness(cs.clone(), || Ok(prior_msg))
                .unwrap();
        let witness_var =
            TxVar::<ScalarFieldMNT6, Config>::new_witness(cs.clone(), || Ok(witness)).unwrap();
        let base_case_var =
            Boolean::<ScalarFieldMNT6>::new_witness(cs.clone(), || Ok(base_case)).unwrap();
        tcp.generate_constraints(
            cs.clone(),
            &msg_var,
            &witness_var,
            &[prior_msg_var],
            &base_case_var,
        )
        .unwrap();

        assert_eq!(cs.is_satisfied().unwrap(), expected_result);
    }

    #[test]
    fn base_case_is_ok() {
        let genesis_txid = transactions()[0].hash().0;
        let input_index = 0u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(
            &transactions()[1].clone(),
            input_index,
            &genesis_txid,
        );
        let prior_msg = msg.clone(); // Can be anything
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(), // Can be anything
            true,
            true,
        );
    }

    #[test]
    fn base_case_with_bad_tx_fails() {
        let genesis_txid = transactions()[0].hash().0;
        let input_index = 0u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(
            &transactions()[2].clone(),
            input_index,
            &genesis_txid,
        ); // Wrong transaction: its parent is not the genesis
        let prior_msg = msg.clone(); // Can be anything
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(), // Can be anything
            true,
            false,
        );
    }

    #[test]
    fn base_case_with_bad_index_fails() {
        let mut bad_tx = transactions()[1].clone();
        bad_tx.inputs = [TxIn {
            prev_output: OutPoint {
                hash: bad_tx.inputs[0].prev_output.hash,
                index: 1, // Not primary chain
            },
            unlock_script: bad_tx.inputs[0].unlock_script.clone(),
            sequence: bad_tx.inputs[0].sequence,
        }]
        .to_vec();

        let genesis_txid = transactions()[0].hash().0;
        let input_index = 0u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(&bad_tx, input_index, &genesis_txid); // Wrong outpoint: its not part of a primary chain
        let prior_msg = msg.clone(); // Can be anything

        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(), // Can be anything
            true,
            false,
        );
    }

    #[test]
    fn base_case_with_bad_genesis_and_correct_chain_index_fails() {
        let input_index = 0u32;
        let output_index = 0u32;
        let msg =
            MessageUniversalTCP::new_from_tx(&transactions()[1].clone(), input_index, &[0; 32]); // Bad genesis_txid
        let prior_msg = msg.clone(); // Can be anything
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(),
            true,
            false,
        );
    }

    #[test]
    fn base_case_with_bad_chain_index_and_correct_genesis_fails() {
        let genesis_txid = transactions()[0].hash().0;
        let input_index = 1u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(
            &transactions()[1].clone(),
            input_index,
            &genesis_txid,
        ); // Bad input_index
        let prior_msg = msg.clone(); // Can be anything
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(),
            true,
            false,
        );
    }

    #[test]
    fn recursive_case_is_ok() {
        let genesis_txid = transactions()[0].hash().0;
        let input_index = 0u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(
            &transactions()[2].clone(),
            input_index,
            &genesis_txid,
        );
        let prior_msg: MessageUniversalTCP = MessageUniversalTCP::new_from_tx(
            &transactions()[1].clone(),
            input_index,
            &genesis_txid,
        );
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(),
            false,
            true,
        );
    }

    #[test]
    fn recursive_case_with_bad_tx_fails() {
        let genesis_txid = transactions()[0].hash().0;
        let input_index = 0u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(
            &transactions()[2].clone(),
            input_index,
            &genesis_txid,
        );
        let prior_msg = msg.clone(); // Wrong transaction, is not the previous one
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(), // **NOTE**: The witness is correct
            false,
            false,
        );
    }

    #[test]
    fn recursive_case_with_bad_index_fails() {
        let mut bad_tx = transactions()[2].clone();
        bad_tx.inputs = [TxIn {
            prev_output: OutPoint {
                hash: bad_tx.inputs[0].prev_output.hash,
                index: 1, // Not primary chain
            },
            unlock_script: bad_tx.inputs[0].unlock_script.clone(),
            sequence: bad_tx.inputs[0].sequence,
        }]
        .to_vec();

        let genesis_txid = transactions()[0].hash().0;
        let input_index = 0u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(&bad_tx, input_index, &genesis_txid);
        let prior_msg = MessageUniversalTCP::new_from_tx(
            &transactions()[1].clone(),
            input_index,
            &genesis_txid,
        ); // The prior message is correct

        test_predicate(
            input_index,
            output_index,
            msg, // Wrong input: its not part of a primary chain
            prior_msg,
            transactions()[1].clone().into(), // Witness is correct
            false,
            false,
        );
    }

    #[test]
    fn recursive_case_with_bad_genesis_and_correct_chain_index_fails() {
        let genesis_txid = transactions()[0].hash().0;
        let input_index = 0u32;
        let output_index = 0u32;
        let msg =
            MessageUniversalTCP::new_from_tx(&transactions()[2].clone(), input_index, &[0; 32]);
        let prior_msg = MessageUniversalTCP::new_from_tx(
            &transactions()[1].clone(),
            input_index,
            &genesis_txid,
        ); // The prior message is correct
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(), // The witness is correct
            false,
            false,
        );
    }

    #[test]
    fn recursive_case_with_bad_chain_index_and_correct_genesis_fails() {
        let genesis_txid = transactions()[0].hash().0;
        let input_index = 1u32;
        let output_index = 0u32;
        let msg = MessageUniversalTCP::new_from_tx(
            &transactions()[2].clone(),
            input_index,
            &genesis_txid,
        ); // Bad input_index
        let prior_msg = MessageUniversalTCP::new_from_tx(
            &transactions()[1].clone(),
            input_index,
            &genesis_txid,
        ); // The prior message is correct
        test_predicate(
            input_index,
            output_index,
            msg,
            prior_msg,
            transactions()[1].clone().into(),
            false,
            false,
        );
    }
}
