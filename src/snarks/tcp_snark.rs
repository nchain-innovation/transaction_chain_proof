use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_pcd::PCD as arkPCD;
use bitcoin_r1cs::constraints::tx::TxVarConfig;
use chain_gang::messages::{OutPoint, Tx};
use rand::{CryptoRng, Rng, SeedableRng};

use crate::data_structures::messages::MessageOutPoint;
use crate::data_structures::witnesses::LocalWitnessOutPoint;
use crate::predicates::tcp::TransactionChainProofPredicate;

use crate::error::{SnarkError, SnarkProofGeneration, SnarkSetup, SnarkVerification};

/// The public input of [TransactionChainProofSNARK]
#[derive(Clone)]
pub struct TransactionChainProofPublicInput {
    pub outpoint: OutPoint,
}

impl From<TransactionChainProofPublicInput> for MessageOutPoint {
    fn from(value: TransactionChainProofPublicInput) -> Self {
        Self::new(&value.outpoint)
    }
}

/// The witness of [TransactionChainProofSNARK]
#[derive(Clone)]
pub struct TransactionChainProofWitness<Proof> {
    /// The transaction in [TransactionChainProofPredicate]
    pub tx: Option<Tx>,
    /// The prior proofs of [TransactionChainProofPredicate]
    pub prior_proof: Option<Proof>,
}

/// TransactionChainProofData holds the types of Proof, ProvingKey, and VerifyingKey for [TransactionChainProofSNARK]
pub trait TransactionChainProofData {
    type Proof: Clone;
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
}

/// Wrapper for TransactionChainProof around any PCD
pub struct TransactionChainProofSNARK<F, P, PCD, RO>
where
    F: PrimeField,
    P: TxVarConfig + Clone,
    PCD: arkPCD<F>,
    RO: Rng + CryptoRng + SeedableRng,
{
    _field: PhantomData<F>,
    _tx_config: PhantomData<P>,
    _pcd: PhantomData<PCD>,
    _ro: PhantomData<RO>,
}

impl<F, P, PCD, RO> TransactionChainProofData for TransactionChainProofSNARK<F, P, PCD, RO>
where
    F: PrimeField,
    P: TxVarConfig + Clone,
    PCD: arkPCD<F>,
    RO: Rng + CryptoRng + SeedableRng,
{
    type Proof = PCD::Proof;
    type ProvingKey = PCD::ProvingKey;
    type VerifyingKey = PCD::VerifyingKey;
}

impl<F, P, PCD, RO> Default for TransactionChainProofSNARK<F, P, PCD, RO>
where
    F: PrimeField,
    P: TxVarConfig + Clone,
    PCD: arkPCD<F>,
    RO: Rng + CryptoRng + SeedableRng,
{
    fn default() -> Self {
        Self {
            _field: PhantomData,
            _tx_config: PhantomData,
            _pcd: PhantomData,
            _ro: PhantomData,
        }
    }
}

impl<F, P, PCD, RO> TransactionChainProofSNARK<F, P, PCD, RO>
where
    F: PrimeField,
    P: TxVarConfig + Clone,
    PCD: arkPCD<F>,
    RO: Rng + CryptoRng + SeedableRng,
{
    /// Setup of the SNARK for the given `(genesis_txid, chain_index)`
    pub fn setup(
        genesis_txid: &[u8; 32],
        chain_index: &u32,
    ) -> Result<
        (
            <Self as TransactionChainProofData>::ProvingKey,
            <Self as TransactionChainProofData>::VerifyingKey,
        ),
        SnarkError,
    > {
        // RNG
        let mut rng = RO::from_entropy();
        // TCP Predicate
        let tcp_predicate = TransactionChainProofPredicate::<P>::new(genesis_txid, chain_index);
        // Setup
        PCD::circuit_specific_setup(&tcp_predicate, &mut rng)
            .map_err(|err| (err, SnarkSetup).into())
    }

    /// Prove that `public_input` is part of a transaction chain at index `chain_index` starting at `genesis_txid`
    pub fn prove(
        genesis_txid: &[u8; 32],
        chain_index: &u32,
        pk: &<Self as TransactionChainProofData>::ProvingKey,
        public_input: &TransactionChainProofPublicInput,
        witness: &TransactionChainProofWitness<<Self as TransactionChainProofData>::Proof>,
    ) -> Result<<Self as TransactionChainProofData>::Proof, SnarkError> {
        // RNG
        let mut rng = RO::from_entropy();
        // TCP predicate
        let tcp_predicate = TransactionChainProofPredicate::<P>::new(genesis_txid, chain_index);
        // Unwrap witness values
        let (prior_msgs, local_witness): (&[MessageOutPoint], LocalWitnessOutPoint<P>) =
            match &witness.tx {
                Some(tx) => (
                    &[MessageOutPoint::from_tx(tx.clone(), *chain_index as usize)],
                    tx.clone().into(),
                ),
                None => (&[], LocalWitnessOutPoint::<P>::default()),
            };
        let prior_proofs: &[<Self as TransactionChainProofData>::Proof] = match &witness.prior_proof
        {
            Some(proof) => &[proof.clone()],
            None => &[],
        };
        // Proof
        PCD::prove(
            pk,
            &tcp_predicate,
            &public_input.outpoint.clone().into(),
            &local_witness,
            prior_msgs,
            prior_proofs,
            &mut rng,
        )
        .map_err(|err| (err, SnarkProofGeneration).into())
    }

    /// Verify that `public_input` is part of a transaction chain at index `chain_index` starting at `genesis_txid`
    /// (which have been hard-coded in the verifying key `vk`)
    pub fn verify(
        vk: &<Self as TransactionChainProofData>::VerifyingKey,
        public_input: &TransactionChainProofPublicInput,
        proof: &<Self as TransactionChainProofData>::Proof,
    ) -> Result<bool, SnarkError> {
        // Verification
        PCD::verify::<TransactionChainProofPredicate<P>>(
            vk,
            &public_input.outpoint.clone().into(),
            proof,
        )
        .map_err(|err| (err, SnarkVerification).into())
    }
}

#[cfg(test)]
mod tests {
    use ark_mnt4_298::{
        Fq as ScalarFieldMNT6, Fr as ScalarFieldMNT4, g1::Parameters as ShortWeierstrassParameters,
    };
    use ark_pcd::ec_cycle_pcd::{ECCyclePCD, ECCyclePCDConfig};
    use ark_pcd::variable_length_crh::injective_map::VariableLengthPedersenCRHCompressor;
    use ark_pcd::variable_length_crh::injective_map::constraints::VariableLengthPedersenCRHCompressorGadget;

    use ark_groth16::{Groth16, constraints::Groth16VerifierGadget};
    use ark_mnt4_298::{MNT4_298, constraints::PairingVar as MNT4PairingVar};
    use ark_mnt6_298::{MNT6_298, constraints::PairingVar as MNT6PairingVar};

    use bitcoin_r1cs::constraints::tx::TxVarConfig;
    use chain_gang::{messages::Tx, util::Serializable};
    use rand_chacha::ChaChaRng;

    use std::io::Cursor;

    use super::{
        TransactionChainProofPublicInput, TransactionChainProofSNARK, TransactionChainProofWitness,
    };

    pub struct PCDGroth16Mnt4;
    impl ECCyclePCDConfig<ScalarFieldMNT6, ScalarFieldMNT4> for PCDGroth16Mnt4 {
        type CRH = VariableLengthPedersenCRHCompressor<ChaChaRng, ShortWeierstrassParameters>;
        type CRHGadget =
            VariableLengthPedersenCRHCompressorGadget<ChaChaRng, ShortWeierstrassParameters>;
        type MainSNARK = Groth16<MNT6_298>;
        type HelpSNARK = Groth16<MNT4_298>;
        type MainSNARKGadget = Groth16VerifierGadget<MNT6_298, MNT6PairingVar>;
        type HelpSNARKGadget = Groth16VerifierGadget<MNT4_298, MNT4PairingVar>;
    }
    type TestPCD = ECCyclePCD<ScalarFieldMNT6, ScalarFieldMNT4, PCDGroth16Mnt4>;

    // Test transactions, they form a primary chain (chain_index = 0)
    fn transactions() -> [Tx; 3] {
        [
            Tx::read(
             &mut Cursor::new(hex::decode("0100000001f9f034a0927022546dd779118e90d1125f94c9a8d4a903941d0ccc6a178d200d000000006b4830450221009eda6ae95d014b177f923e7880ca9b95dbe95f7a190eee2c4a223752e1c84fb102200c727fdcd19cbb1f1fad49607b28971925c029f894003cffaf4024f6e13817d8012103c66918716436f526bc5c9ab0919f22bf73c533f782ff066bd4e5b89dd0e61bfcffffffff021e81e21b440000001976a91483e6b5769fd253bd05346aa1a19be451c04fb75388ac80af3c9d000000001976a914ced70e663b2c328d2b936e6775e1adba1eaa6dcb88ac00000000").unwrap())
            ).unwrap(),
            Tx::read(
            &mut Cursor::new(hex::decode("0100000001341da7307fc32e06d68036a84e0baabf22c830ebd269a47be1df02353fae9441000000006b48304502200a948b5cf031e109ec0765b17ba5ee711794175f11a3ae8364f60c4f19186b0c022100961f0dc6f31f0629033b79808784d51767ce9ca309fe64bfce09f570c0507e77012103e482e68bbcbcd35ff631807ae195e5a900e17f99e9dca3351791d5bcfe45e573ffffffff025e04a744430000001976a91443c4d86448cb72885fd0ac4fe327ff6a9e3c34e488acc07c3bd7000000001976a9141e198a0565eefefc7bb55ec91fbbafac386c46bb88ac00000000").unwrap())
            ).unwrap(),
            Tx::read(
            &mut Cursor::new(hex::decode("01000000014dc1cf704186f0e84b026caee01648f2a80157e560bdf4dceb4e17e3c362afba000000006b483045022100e004444791b1c28751a90d9bb72d2544ab5d4dda2ef4d029abac7cb5daed712902207222c01855ab7166f731e78f16a2f7c4d9c5c41c9500fa69d3a0661e9d0993620121022335ec5291beb6fa2233e2db70b9b320184e3d8561ffe57e01fdcb6f8c076fd8ffffffff021e17ec4b420000001976a91477c836b1dcd4da5e112fac5d03c9f1d18465942c88ac40edbaf8000000001976a9141e35a79afdb1ac7082fd96ead06818095df2900e88ac00000000").unwrap())
            ).unwrap()
        ]
    }

    // Structure of the transactions in the chain
    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 1;
        const N_OUTPUTS: usize = 2;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0x6b];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x19, 0x19];
        const LEN_PREV_LOCK_SCRIPT: Option<usize> = None;
        const PRE_SIGHASH_N_INPUT: Option<usize> = None;
    }

    type TestTCPSnark = TransactionChainProofSNARK<ScalarFieldMNT6, Config, TestPCD, ChaChaRng>;

    #[test]
    fn groth16_snark_is_ok() {
        let genesis_tx = transactions()[0].clone();
        let genesis_txid = genesis_tx.hash().0;

        // Setup
        let (pk, vk) = TestTCPSnark::setup(&genesis_txid, &0u32).unwrap();

        // Prove and Verify base case
        let first_tx = transactions()[1].clone();
        let public_input = TransactionChainProofPublicInput {
            outpoint: first_tx.inputs[0].prev_output.clone(),
        };
        let witness = TransactionChainProofWitness {
            tx: None,          // Base case, so None
            prior_proof: None, // Base case, so None
        };
        let proof =
            TestTCPSnark::prove(&genesis_txid, &0u32, &pk, &public_input, &witness).unwrap();
        let is_proof_valid = TestTCPSnark::verify(&vk, &public_input, &proof).unwrap();
        assert!(is_proof_valid);

        // Prove and Verify recursive case
        let second_tx = transactions()[2].clone();
        let public_input = TransactionChainProofPublicInput {
            outpoint: second_tx.inputs[0].prev_output.clone(),
        };
        let witness = TransactionChainProofWitness {
            tx: Some(first_tx.clone()),
            prior_proof: Some(proof.clone()),
        };
        let proof =
            TestTCPSnark::prove(&genesis_txid, &0u32, &pk, &public_input, &witness).unwrap();
        let is_proof_valid = TestTCPSnark::verify(&vk, &public_input, &proof).unwrap();
        assert!(is_proof_valid);
    }
}
