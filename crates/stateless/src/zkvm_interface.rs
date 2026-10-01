//! revm [`Crypto`] and alloy [`CryptoProvider`] implementations using the standard zkVM
//! accelerators ([`ere_platform_zkvm::accelerators`]).

use alloc::{sync::Arc, vec::Vec};

use alloy_consensus::crypto::{CryptoProvider, RecoveryError, install_default_provider};
use alloy_primitives::Address;
use ere_platform_zkvm::accelerators::{
    self as zkvm, Bls12G1MsmPair, Bls12G2MsmPair, Bls12PairingPair, Bn254PairingPair, Bytes,
};
#[cfg(target_vendor = "zisk")]
use revm::precompile::DefaultCrypto;
use revm::precompile::{
    Crypto, PrecompileHalt,
    bls12_381::{G1Point, G1PointScalar, G2Point, G2PointScalar},
};

/// Installs [`ZkVMInterfaceCrypto`] as [`revm::precompile::Crypto`] backend and as
/// [`alloy_consensus::crypto::CryptoProvider`].
///
/// # Panics
///
/// Panics if a revm or Alloy crypto backend has already been installed.
pub fn install_crypto() {
    assert!(revm::install_crypto(ZkVMInterfaceCrypto));
    install_default_provider(Arc::new(ZkVMInterfaceCrypto)).unwrap();
}

/// revm and Alloy crypto provider backed by the standard zkVM interface.
#[derive(Debug, Default)]
struct ZkVMInterfaceCrypto;

impl Crypto for ZkVMInterfaceCrypto {
    #[inline]
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        sha256(input)
    }

    #[inline]
    fn blake2_compress(&self, rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
        zkvm::blake2f(rounds, h, m, t, f).expect("blake2f failed");
    }

    #[inline]
    fn ripemd160(&self, input: &[u8]) -> [u8; 32] {
        zkvm::ripemd160(input).expect("ripemd160 failed")
    }

    #[inline]
    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        zkvm::modexp(base, exp, modulus).map_err(|_| PrecompileHalt::other("modexp failed"))
    }

    #[inline]
    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let pubkey = zkvm::secp256k1_ecrecover(msg, sig, recid)
            .map_err(|_| PrecompileHalt::Secp256k1RecoverFailed)?;
        let mut hash = keccak256(&pubkey);
        hash[..12].fill(0);
        Ok(hash)
    }

    #[inline]
    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        zkvm::secp256r1_verify(msg, sig, pk) == Ok(true)
    }

    #[inline]
    fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        let p1 = p1.try_into().map_err(|_| PrecompileHalt::other("bn254 g1_add bad p1 len"))?;
        let p2 = p2.try_into().map_err(|_| PrecompileHalt::other("bn254 g1_add bad p2 len"))?;
        zkvm::bn254_g1_add(p1, p2).map_err(|_| PrecompileHalt::other("bn254_g1_add failed"))
    }

    #[inline]
    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        let point =
            point.try_into().map_err(|_| PrecompileHalt::other("bn254 g1_mul bad point len"))?;
        let scalar =
            scalar.try_into().map_err(|_| PrecompileHalt::other("bn254 g1_mul bad scalar len"))?;
        zkvm::bn254_g1_mul(point, scalar).map_err(|_| PrecompileHalt::other("bn254_g1_mul failed"))
    }

    #[inline]
    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        let pairs: Vec<Bn254PairingPair> = pairs
            .iter()
            .map(|(g1, g2)| Bn254PairingPair {
                g1: Bytes((*g1).try_into().unwrap()),
                g2: Bytes((*g2).try_into().unwrap()),
            })
            .collect();
        zkvm::bn254_pairing(&pairs).map_err(|_| PrecompileHalt::other("bn254_pairing failed"))
    }

    #[inline]
    fn bls12_381_g1_add(&self, a: G1Point, b: G1Point) -> Result<[u8; 96], PrecompileHalt> {
        zkvm::bls12_g1_add(&pack_bls12_381_g1(&a), &pack_bls12_381_g1(&b))
            .map_err(|_| PrecompileHalt::Bls12381G1NotOnCurve)
    }

    #[inline]
    fn bls12_381_g1_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<G1PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; 96], PrecompileHalt> {
        #[cfg(target_vendor = "zisk")]
        let pairs = {
            let pairs = pairs.collect::<Result<Vec<_>, _>>()?;
            validate_zisk_bls12_g1_subgroups(pairs.iter().map(|(point, _)| *point))?;
            pairs.into_iter().map(Ok)
        };

        let pairs: Vec<Bls12G1MsmPair> = pairs
            .map(|pair| {
                let (point, scalar) = pair?;
                Ok(Bls12G1MsmPair {
                    point: Bytes(pack_bls12_381_g1(&point)),
                    scalar: Bytes(scalar),
                })
            })
            .collect::<Result<_, PrecompileHalt>>()?;
        zkvm::bls12_g1_msm(&pairs).map_err(|_| PrecompileHalt::Bls12381G1NotOnCurve)
    }

    #[inline]
    fn bls12_381_g2_add(&self, a: G2Point, b: G2Point) -> Result<[u8; 192], PrecompileHalt> {
        zkvm::bls12_g2_add(&pack_bls12_381_g2(&a), &pack_bls12_381_g2(&b))
            .map_err(|_| PrecompileHalt::Bls12381G2NotOnCurve)
    }

    #[inline]
    fn bls12_381_g2_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<G2PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; 192], PrecompileHalt> {
        let pairs: Vec<Bls12G2MsmPair> = pairs
            .map(|pair| {
                let (point, scalar) = pair?;
                Ok(Bls12G2MsmPair {
                    point: Bytes(pack_bls12_381_g2(&point)),
                    scalar: Bytes(scalar),
                })
            })
            .collect::<Result<_, PrecompileHalt>>()?;
        zkvm::bls12_g2_msm(&pairs).map_err(|_| PrecompileHalt::Bls12381G2NotOnCurve)
    }

    #[inline]
    fn bls12_381_pairing_check(
        &self,
        pairs: &[(G1Point, G2Point)],
    ) -> Result<bool, PrecompileHalt> {
        #[cfg(target_vendor = "zisk")]
        validate_zisk_bls12_g1_subgroups(pairs.iter().map(|(point, _)| *point))?;

        let pairs: Vec<Bls12PairingPair> = pairs
            .iter()
            .map(|(g1, g2)| Bls12PairingPair {
                g1: Bytes(pack_bls12_381_g1(g1)),
                g2: Bytes(pack_bls12_381_g2(g2)),
            })
            .collect();
        zkvm::bls12_pairing(&pairs).map_err(|_| PrecompileHalt::other("bls12_381_pairing failed"))
    }

    #[inline]
    fn bls12_381_fp_to_g1(&self, fp: &[u8; 48]) -> Result<[u8; 96], PrecompileHalt> {
        // The ZisK hint panics on valid EIP-2537 isogeny-kernel inputs.
        #[cfg(target_vendor = "zisk")]
        return DefaultCrypto.bls12_381_fp_to_g1(fp);

        #[cfg(not(target_vendor = "zisk"))]
        zkvm::bls12_map_fp_to_g1(fp).map_err(|_| PrecompileHalt::other("bls12_381_fp_to_g1 failed"))
    }

    #[inline]
    fn bls12_381_fp2_to_g2(&self, fp2: ([u8; 48], [u8; 48])) -> Result<[u8; 192], PrecompileHalt> {
        let mut data = [0u8; 96];
        data[..48].copy_from_slice(&fp2.0);
        data[48..].copy_from_slice(&fp2.1);
        zkvm::bls12_map_fp2_to_g2(&data)
            .map_err(|_| PrecompileHalt::other("bls12_381_fp2_to_g2 failed"))
    }

    #[inline]
    fn verify_kzg_proof(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), PrecompileHalt> {
        (zkvm::kzg_point_eval(commitment, z, y, proof) == Ok(true))
            .then_some(())
            .ok_or(PrecompileHalt::BlobVerifyKzgProofFailed)
    }
}

impl CryptoProvider for ZkVMInterfaceCrypto {
    #[inline]
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let pubkey = zkvm::secp256k1_ecrecover(msg, sig[..64].try_into().unwrap(), sig[64])
            .map_err(|_| RecoveryError::new())?;
        let hash = keccak256(&pubkey);
        Ok(Address::from_slice(&hash[12..]))
    }

    #[inline]
    fn verify_and_compute_signer_unchecked(
        &self,
        pubkey: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let pubkey = uncompressed_pubkey_coordinates(pubkey)?;
        if zkvm::secp256k1_verify(msg, sig, pubkey) != Ok(true) {
            return Err(RecoveryError::new());
        }
        let hash = keccak256(pubkey);
        Ok(Address::from_slice(&hash[12..]))
    }
}

#[inline]
fn uncompressed_pubkey_coordinates(pubkey: &[u8; 65]) -> Result<&[u8; 64], RecoveryError> {
    if pubkey[0] != 0x04 {
        return Err(RecoveryError::new());
    }
    Ok(pubkey[1..].try_into().expect("public key coordinates have a fixed length"))
}

#[inline]
/// Computes a SHA-256 digest using the standard zkVM interface.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    zkvm::sha256(data).expect("sha256 failed")
}

#[inline]
fn keccak256(data: &[u8]) -> [u8; 32] {
    zkvm::keccak256(data).expect("keccak256 failed")
}

#[cfg(target_vendor = "zisk")]
fn validate_zisk_bls12_g1_subgroups(
    points: impl Iterator<Item = G1Point>,
) -> Result<(), PrecompileHalt> {
    // ZisK's G1 MSM and pairing hints panic instead of rejecting non-subgroup points.
    let mut points = points.collect::<Vec<_>>();
    points.sort_unstable();
    points.dedup();
    let mut pairs = points.into_iter().map(|point| Ok((point, [0; 32])));
    DefaultCrypto.bls12_381_g1_msm(&mut pairs).map(|_| ())
}

#[inline]
fn pack_bls12_381_g1(p: &G1Point) -> [u8; 96] {
    let mut data = [0u8; 96];
    data[..48].copy_from_slice(&p.0);
    data[48..].copy_from_slice(&p.1);
    data
}

#[inline]
fn pack_bls12_381_g2(p: &G2Point) -> [u8; 192] {
    let mut data = [0u8; 192];
    data[..48].copy_from_slice(&p.0);
    data[48..96].copy_from_slice(&p.1);
    data[96..144].copy_from_slice(&p.2);
    data[144..].copy_from_slice(&p.3);
    data
}

#[cfg(test)]
mod tests {
    use super::uncompressed_pubkey_coordinates;

    #[test]
    fn validates_uncompressed_public_key_prefix() {
        let mut public_key = [0u8; 65];
        assert!(uncompressed_pubkey_coordinates(&public_key).is_err());

        public_key[0] = 0x04;
        assert!(uncompressed_pubkey_coordinates(&public_key).is_ok());
    }
}
